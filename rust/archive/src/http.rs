//! The archive's HTTP surface: the existing parser, and a response type that cannot carry a
//! verdict.
//!
//! # What is reused, and what is deliberately not
//!
//! **Reused:** [`warrantor_warrant::serve::parse_request_with`], [`warrantor_warrant::serve::status`]
//! and the framing discipline behind them — refuse every `Transfer-Encoding`, validate path
//! segments and never percent-decode them, cap every line read, one request per connection,
//! `Connection: close`. That is the part most worth not rewriting: a second HTTP parser is a second
//! place a smuggled request can be got wrong, and this surface faces a network rather than a
//! loopback socket. Only the body cap differs, and a constant is not a reason for another parser.
//!
//! **Not reused: [`warrantor_warrant::serve::Response`].** Its `json` constructor forces
//! `{"verified": …, "verification": {…}, "data": …}` onto every body. On the local agent that
//! envelope is correct — the verdict is computed in Rust on the operator's own machine from their
//! own store. On a *remote* archive the same field would be a verdict computed by a machine the
//! audited party's engineers may control, and a console rendering `verified` would be rendering it.
//! That is precisely "the backend became an authority", so this module defines its own
//! [`ArchiveResponse`] whose closest equivalent field is named `not_a_verdict`. The name is the
//! guardrail; `tests/the_archive_never_serves_a_verdict.rs` is what keeps it one.
//!
//! # The route table, kept short so it can be checked on sight
//!
//! | Route | Method | What it does |
//! |---|---|---|
//! | `/v1/health` | GET | version and liveness; no store data |
//! | `/v1/evidence` | POST | file an artifact |
//! | `/v1/evidence/{sha256}` | GET | the stored bytes, verbatim |
//! | `/v1/warrants/{id}/evidence` | GET | what is held about one warrant |
//! | `/v1/summary` | GET | custody totals across everything held |
//! | `/v1/devices/enrol` | POST | claim a one-time code with a public key |
//!
//! There is **no settle, void, stop or grant**, and there is no route that accepts warrant claims
//! and returns something signed. The archive holds no key that could perform one of those acts, and
//! the table is short enough that a route which did would be visible in review. A convenience
//! endpoint that notarised a submission would move warrant-minting authority into a
//! network-reachable process, which is the one thing W1 forbids outright.
//!
//! # No CORS header, here either
//!
//! W1's no-CORS rule is written about the local agent, and this is a genuinely remote service, so
//! the rule does not transfer automatically. It is still not added: **no browser client talks to
//! this archive in stage 1**, and a header added before the client exists is a header nobody
//! reviewed against a real threat. Adding one later should be a documented decision with a named
//! origin, not a default that arrived early.

use std::io::BufRead;

use serde_json::{json, Value};

use warrantor_warrant::serve::{is_warrant_id, status, HttpRequest, Limits, Response};

use crate::artifact::{ingest, ArtifactKind, IngestError};
use crate::device::{self, DeviceError};
use crate::store::{ArchiveStore, EnrolError, ListFilter, PutOutcome};
use crate::ARCHIVE_RESPONSE_FORMAT;

/// The archive's framing caps.
///
/// Identical to [`Limits::DEFAULT`] except for the body. 4 MiB rather than 64 KiB because an
/// exported report bundle carrying a long changed-files list and a full limitations block will
/// exceed the smaller number, and a cap that refuses real evidence is a cap that teaches people to
/// stop filing it. It is a cap and not an absence of one: an unbounded body on a network-facing
/// service is how one client exhausts the process.
pub const ARCHIVE_LIMITS: Limits = Limits {
    request_line: 8 * 1024,
    header_bytes: 16 * 1024,
    headers: 64,
    body_bytes: 4 * 1024 * 1024,
};

/// Default port. Loopback only unless a bind address is given explicitly.
pub const DEFAULT_PORT: u16 = 8788;

/// The sentence every response carries about what the archive's own opinion is worth.
pub const VERIFY_LOCALLY: &str =
    "This archive relays bytes it did not produce and cannot forge. Its ingest check is door \
     hygiene and is NOT a verdict: verify locally with `warrantor verify <file> --issuer <hex>`, \
     against an issuer key you obtained out of band.";

/// One archive response, ready to write.
///
/// Two constructors and no third. Neither can produce a field named `verified` or `verification`,
/// which is what makes "this server never serves a verdict" a property of the type rather than a
/// discipline applied at every handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveResponse {
    /// HTTP status.
    pub status: u16,
    /// The JSON body, when this is a JSON answer.
    pub body: Value,
    /// Pre-encoded bytes and their content type, when this response is a stored artifact.
    ///
    /// The one response whose body the archive did not compose. Stored bytes are returned
    /// **verbatim** — not re-serialised through `serde_json`, because a faithful round trip is
    /// still the archive choosing the bytes, and "the archive returns what it was given" is the
    /// claim that makes verifying off the archive worth anything.
    pub raw: Option<(&'static str, Vec<u8>)>,
}

impl ArchiveResponse {
    /// A successful answer.
    ///
    /// `not_a_verdict` carries the door's three-valued note and the sentence telling the reader
    /// where a real answer comes from. The field is named the way it is because a viewer renders
    /// what it is handed, and the only reliable defence against a field being rendered as a verdict
    /// is a name no designer would put next to a green tick.
    #[must_use]
    pub fn ok(data: Value, ingest_check: &str, reason: &str) -> Self {
        Self {
            status: status::OK,
            body: json!({
                "format": ARCHIVE_RESPONSE_FORMAT,
                "data": data,
                "not_a_verdict": {
                    "ingest_check": ingest_check,
                    "reason": reason,
                    "verify_locally": VERIFY_LOCALLY,
                },
            }),
            raw: None,
        }
    }

    /// A refusal: a stable machine code and a sentence phrased about the caller's request.
    #[must_use]
    pub fn error(status: u16, code: &str, message: &str) -> Self {
        Self {
            status,
            body: json!({
                "format": ARCHIVE_RESPONSE_FORMAT,
                "error": { "code": code, "message": message },
                "not_a_verdict": {
                    "ingest_check": "unknown",
                    "reason": "nothing was checked: the request was refused before any artifact \
                               was read.",
                    "verify_locally": VERIFY_LOCALLY,
                },
            }),
            raw: None,
        }
    }

    /// The stored bytes of one artifact, exactly as they were submitted.
    #[must_use]
    pub fn artifact_bytes(bytes: Vec<u8>) -> Self {
        Self {
            status: status::OK,
            body: Value::Null,
            raw: Some(("application/json", bytes)),
        }
    }
}

/// Write one response. The only place bytes leave this module.
///
/// The same three hardening headers `serve.rs` writes, and the same `Connection: close`. No
/// `Access-Control-Allow-Origin`, ever — see this module's doc.
///
/// # Errors
/// I/O failures on the writer only.
pub fn write_response<W: std::io::Write>(
    out: &mut W,
    response: &ArchiveResponse,
) -> std::io::Result<()> {
    let (content_type, body) = match &response.raw {
        Some((content_type, bytes)) => (*content_type, bytes.clone()),
        None => (
            "application/json",
            serde_json::to_vec(&response.body).unwrap_or_else(|_| {
                // Unreachable with a body the two constructors built, and handled anyway: the
                // release profile is `panic = "abort"`, so "cannot happen" is not a licence to
                // unwrap in a thread-per-connection server.
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
    out.write_all(b"\r\n")?;
    out.write_all(&body)?;
    out.flush()
}

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

/// Translate a framing refusal from the shared parser into this module's response type.
///
/// Reads the public `status` and `error` fields off the [`Response`] `parse_request_with` returned,
/// with a fixed fallback rather than an unwrap. The fallback exists because this runs on a
/// connection thread in a `panic = "abort"` process, where indexing into a JSON body that turned
/// out to be shaped differently would take the whole server down over a malformed request line.
#[must_use]
pub fn from_framing_refusal(refusal: &Response) -> ArchiveResponse {
    let code = refusal
        .body
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("malformed_request");
    let message = refusal
        .body
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("this request could not be read as HTTP/1.1");
    ArchiveResponse::error(refusal.status, code, message)
}

/// Read one request off a reader, using the shared parser with the archive's caps.
///
/// # Errors
/// The [`ArchiveResponse`] that should be written back.
pub fn parse<R: BufRead>(input: &mut R) -> Result<HttpRequest, ArchiveResponse> {
    warrantor_warrant::serve::parse_request_with(input, &ARCHIVE_LIMITS)
        .map_err(|refusal| from_framing_refusal(&refusal))
}

// ── routing ───────────────────────────────────────────────────────────────────────────

/// The routes, and the single method each accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Health,
    Submit,
    Fetch(String),
    ListForWarrant(String),
    Summary,
    Enrol,
}

/// Is this a SHA-256 hex digest? Validated before it reaches a query parameter.
fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn resolve(segments: &[String]) -> Result<(Target, &'static str), ArchiveResponse> {
    let parts: Vec<&str> = segments.iter().map(String::as_str).collect();
    match parts.as_slice() {
        ["v1", "health"] => Ok((Target::Health, "GET")),
        ["v1", "evidence"] => Ok((Target::Submit, "POST")),
        ["v1", "devices", "enrol"] => Ok((Target::Enrol, "POST")),
        ["v1", "evidence", digest] => {
            if !is_digest(digest) {
                return Err(ArchiveResponse::error(
                    status::BAD_REQUEST,
                    "malformed_digest",
                    "an artifact is addressed by its 64-character SHA-256 hex digest",
                ));
            }
            Ok((Target::Fetch((*digest).to_string()), "GET"))
        }
        ["v1", "warrants", id, "evidence"] => {
            if !is_warrant_id(id) {
                return Err(ArchiveResponse::error(
                    status::BAD_REQUEST,
                    "malformed_warrant_id",
                    "a warrant id is wrt_ followed by up to 64 letters, digits, underscores or \
                     hyphens",
                ));
            }
            Ok((Target::ListForWarrant((*id).to_string()), "GET"))
        }
        ["v1", "summary"] => Ok((Target::Summary, "GET")),
        _ => Err(no_such_route()),
    }
}

fn no_such_route() -> ArchiveResponse {
    ArchiveResponse::error(
        status::NOT_FOUND,
        "no_such_route",
        "this archive serves GET /v1/health, POST /v1/evidence, GET /v1/evidence/{sha256}, GET \
         /v1/warrants/{id}/evidence, GET /v1/summary and POST /v1/devices/enrol. There is \
         deliberately no settle, \
         void, stop or grant: this server holds no key that could perform one.",
    )
}

/// The path a device signature covers, rebuilt from the validated segments.
///
/// Rebuilt rather than taken from the raw request line, so the bytes the signature is checked
/// against are the bytes the router will act on. Checking a signature over the raw target and then
/// routing on a normalised one is the classic gap where the two disagree.
fn canonical_path(segments: &[String]) -> String {
    let mut path = String::from("/");
    path.push_str(&segments.join("/"));
    path
}

/// Handle one parsed request, start to finish.
///
/// `/v1/health` is answered **before** authentication, and nothing else is. It reads no store data
/// and is byte-identical across archives, so it can say "this process is up" to a load balancer
/// without becoming a way to probe whether an archive holds anything. Every other route
/// authenticates first, so an unauthenticated caller gets the same refusal for a digest that exists
/// and one that does not, and cannot enumerate what is held.
pub fn handle<S: ArchiveStore>(store: &mut S, request: &HttpRequest, now: u64) -> ArchiveResponse {
    let (target, allowed) = match resolve(&request.segments) {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    if request.method != allowed {
        return ArchiveResponse::error(
            status::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "that route accepts a different method",
        );
    }
    if target == Target::Health {
        return health(now);
    }

    // Enrolment is the one authenticated-by-something-else route: a device that is enrolling has no
    // key on file yet, so it presents the one-time code instead. Everything else needs a signature.
    if target == Target::Enrol {
        return enrol(store, request, now);
    }

    let credential = match device::parse_credential(request.authorization.as_deref()) {
        Ok(credential) => credential,
        Err(e) => return unauthorized(&e),
    };
    let path = canonical_path(&request.segments);
    let device = match device::authenticate(
        store,
        &credential,
        &request.method,
        &path,
        &request.body,
        now,
    ) {
        Ok(device) => device,
        Err(e) => return unauthorized(&e),
    };

    match target {
        Target::Health | Target::Enrol => unreachable(),
        Target::Submit => submit(store, request, &device.id, now),
        Target::Fetch(digest) => fetch(store, &digest),
        Target::ListForWarrant(id) => list_for_warrant(store, &id),
        Target::Summary => summary(store),
    }
}

/// Both arms above returned already. A refusal rather than `unreachable!()`, because the release
/// profile aborts on panic and a routing change that made this reachable would take the server down
/// instead of answering.
fn unreachable() -> ArchiveResponse {
    ArchiveResponse::error(
        status::INTERNAL,
        "internal",
        "this request could not be dispatched",
    )
}

/// Every authentication failure answers 401 with the same body.
///
/// The reason word is carried, because an operator debugging a clock-skew problem needs to know it
/// is clock skew and a replayed nonce is worth naming. What is never carried *to an unauthenticated
/// caller* is whether the device exists: `UnknownDevice` and `BadSignature` both read as a refusal
/// about this request, so the route cannot be used to enumerate enrolled devices.
///
/// `device_revoked` is the one code that says something about a device, and it is reachable only
/// behind a valid signature — `device::authenticate` checks revocation *after* `verify_strict`
/// precisely so this code cannot be got out of the route by someone signing with a key they
/// invented. Whoever sees it is holding that device's private key, and telling that person their
/// device was revoked is the point of the code rather than a leak.
fn unauthorized(error: &DeviceError) -> ArchiveResponse {
    let (code, message) =
        match error {
            DeviceError::Stale { .. } => ("stale_request", error.to_string()),
            DeviceError::Replay => ("replayed_nonce", error.to_string()),
            DeviceError::Revoked => ("device_revoked", error.to_string()),
            DeviceError::Store(_) => return ArchiveResponse::error(
                status::UNAVAILABLE,
                "store_unavailable",
                "the archive could not reach its store, so this request was not answered. Nothing \
                 was written.",
            ),
            _ => (
                "unauthorized",
                "this request did not carry a usable device signature".to_string(),
            ),
        };
    ArchiveResponse::error(status::UNAUTHORIZED, code, &message)
}

/// Liveness, and deliberately nothing else.
///
/// This body once also served `"append_only": true`, `"holds_no_signing_key": true` and
/// `"routes_that_mutate_a_warrant": 0`. They are gone, and their absence is the point. They were
/// literals — not derived from a `pg_trigger` lookup, not from grant introspection, not from
/// anything — so a compromised archive that had acquired a signing key or had its trigger dropped
/// returned the identical three values, unauthenticated, to a viewer that would render them as
/// badges. That is the same failure the `not_a_verdict` naming discipline exists to prevent, one
/// level up: **a machine asserting its own trustworthiness is not evidence of it**, and the walker
/// in `tests/the_archive_never_serves_a_verdict.rs` now bans the shape as well as the word.
///
/// Whether this archive is append-only is answered by reading `migrations/0001_initial.sql` and by
/// verifying artifacts off the archive, never by asking the archive.
fn health(now: u64) -> ArchiveResponse {
    ArchiveResponse::ok(
        json!({
            "service": "warrantor-archive",
            "version": env!("CARGO_PKG_VERSION"),
            "now": now,
        }),
        "unknown",
        "health reads no artifact, so nothing was checked.",
    )
}

fn submit<S: ArchiveStore>(
    store: &mut S,
    request: &HttpRequest,
    device_id: &str,
    now: u64,
) -> ArchiveResponse {
    let ingested = match ingest(request.body.clone()) {
        Ok(ingested) => ingested,
        Err(e) => {
            let code = match e {
                IngestError::NotJson => "not_json",
                IngestError::NoFormat => "no_format",
                IngestError::UnknownFormat { .. } => "unknown_format",
                IngestError::NoWarrantId { .. } => "no_warrant_id",
            };
            return ArchiveResponse::error(status::BAD_REQUEST, code, &e.to_string());
        }
    };
    // Note what is NOT here: no branch on `ingested.check`. An artifact whose signatures do not
    // verify is stored, returned byte for byte, and marked. A tampered file is the single most
    // important thing to be able to put in front of a human, and an archive that refused to hold
    // one would be destroying the evidence that it existed.
    let outcome = match store.put_artifact(&ingested, device_id, now) {
        Ok(outcome) => outcome,
        Err(_) => {
            return ArchiveResponse::error(
                status::UNAVAILABLE,
                "store_unavailable",
                "the archive could not write to its store, so nothing was filed. Retry: this \
                 submission is idempotent on its digest, so a retry cannot create a duplicate.",
            )
        }
    };
    ArchiveResponse::ok(
        json!({
            "digest": ingested.digest,
            "kind": ingested.kind.word(),
            "warrant_id": ingested.warrant_id,
            "already_held": outcome == PutOutcome::AlreadyHeld,
            "submitted_by_device": device_id,
            "submitted_at": now,
        }),
        ingested.check.word(),
        ingested.check.reason(),
    )
}

fn fetch<S: ArchiveStore>(store: &S, digest: &str) -> ArchiveResponse {
    match store.get_artifact(digest) {
        Err(_) => ArchiveResponse::error(
            status::UNAVAILABLE,
            "store_unavailable",
            "the archive could not read its store, so this artifact was not returned.",
        ),
        Ok(None) => ArchiveResponse::error(
            status::NOT_FOUND,
            "no_such_artifact",
            "this archive holds no artifact with that digest",
        ),
        // Verbatim, with no envelope around it. The bytes a client verifies must be exactly the
        // bytes that were filed: wrapping them in an object would force the client to unwrap and
        // re-serialise, and the re-serialisation would change the digest.
        Ok(Some(artifact)) => ArchiveResponse::artifact_bytes(artifact.bytes),
    }
}

fn list_for_warrant<S: ArchiveStore>(store: &S, warrant_id: &str) -> ArchiveResponse {
    let filter = ListFilter {
        warrant_id: Some(warrant_id.to_string()),
        kind: None,
    };
    match store.list_artifacts(&filter) {
        Err(_) => ArchiveResponse::error(
            status::UNAVAILABLE,
            "store_unavailable",
            "the archive could not read its store, so this listing was not produced. An empty \
             list would have been indistinguishable from an archive that holds nothing.",
        ),
        Ok(rows) => ArchiveResponse::ok(
            json!({
                "warrant_id": warrant_id,
                "artifacts": rows,
                "kinds_held": [
                    ArtifactKind::Report.word(),
                    ArtifactKind::Stop.word(),
                    ArtifactKind::Ledger.word(),
                ],
            }),
            "unknown",
            "a listing reads no artifact body, so no signature was checked for these rows. Each \
             row's ingest_check is the note taken at the door when it was filed.",
        ),
    }
}

/// Custody totals across everything this archive holds — the fleet-level view a decision-maker
/// asks for that no single machine can answer.
///
/// Computed from the same `list_artifacts` a per-warrant listing uses, with the empty filter, so
/// the summary and the listings can never disagree about what is held: they are the same read,
/// aggregated. It is a summary **of custody records** — what arrived, from which devices, about
/// which warrants, when — and nothing here read an artifact body or formed an opinion about one.
/// The `not_a_verdict` block says so, as on every route.
///
/// A store that cannot be read is a refusal, never a summary of nothing — the same rule the
/// listing already keeps.
fn summary<S: ArchiveStore>(store: &S) -> ArchiveResponse {
    let filter = ListFilter::default();
    let rows = match store.list_artifacts(&filter) {
        Err(_) => {
            return ArchiveResponse::error(
                status::UNAVAILABLE,
                "store_unavailable",
                "the archive could not read its store, so this summary was not produced. An \
                 empty summary would have been indistinguishable from an archive that holds \
                 nothing.",
            )
        }
        Ok(rows) => rows,
    };
    let mut warrants = std::collections::BTreeSet::new();
    let mut devices = std::collections::BTreeSet::new();
    let mut by_kind = std::collections::BTreeMap::<String, u64>::new();
    let mut by_device = std::collections::BTreeMap::<String, u64>::new();
    let mut first_filed_at = u64::MAX;
    let mut last_filed_at = u64::MIN;
    for row in &rows {
        warrants.insert(row.warrant_id.clone());
        devices.insert(row.submitted_by_device.clone());
        *by_kind.entry(row.kind.word().to_string()).or_insert(0) += 1;
        *by_device
            .entry(row.submitted_by_device.clone())
            .or_insert(0) += 1;
        first_filed_at = first_filed_at.min(row.submitted_at);
        last_filed_at = last_filed_at.max(row.submitted_at);
    }
    ArchiveResponse::ok(
        json!({
            "artifacts": rows.len(),
            "warrants": warrants.len(),
            "devices": devices.len(),
            "first_filed_at": if rows.is_empty() { serde_json::Value::Null } else { json!(first_filed_at) },
            "last_filed_at": if rows.is_empty() { serde_json::Value::Null } else { json!(last_filed_at) },
            "by_kind": by_kind,
            "by_device": by_device,
        }),
        "unknown",
        "a summary reads no artifact body, so no signature was checked for anything it counts. \
         It is an account of custody records — what arrived, from which devices, when — and not \
         an opinion about any of it.",
    )
}

fn enrol<S: ArchiveStore>(store: &mut S, request: &HttpRequest, now: u64) -> ArchiveResponse {
    let malformed = || {
        ArchiveResponse::error(
            status::BAD_REQUEST,
            "malformed_body",
            "enrolment takes {\"code\": \"<one-time code>\", \"public_key\": \"<64 hex chars>\"}",
        )
    };
    let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&request.body) else {
        return malformed();
    };
    let (Some(code), Some(public_key)) = (
        body.get("code").and_then(Value::as_str),
        body.get("public_key").and_then(Value::as_str),
    ) else {
        return malformed();
    };
    // The key is parsed before the code is spent. A device that presents a valid code and a
    // malformed key would otherwise burn the code and be unable to retry with a correct one.
    if device::parse_public_key(public_key).is_err() {
        return ArchiveResponse::error(
            status::BAD_REQUEST,
            "malformed_public_key",
            "a device public key is a 64-character hex Ed25519 verifying key",
        );
    }
    let device_id =
        match device::mint_device_id() {
            Ok(id) => id,
            Err(_) => return ArchiveResponse::error(
                status::INTERNAL,
                "no_randomness",
                "the archive could not mint a device identifier and refuses to enrol without one",
            ),
        };
    let digest = crate::device::EnrolmentCode::digest_of(code);
    match store.enrol_device(&digest, &device_id, public_key, now) {
        Ok(device) => ArchiveResponse::ok(
            json!({
                "device_id": device.id,
                "label": device.label,
                "enrolled_at": device.enrolled_at,
                "sign_requests_as": format!(
                    "{} <device_id>.<timestamp>.<nonce>.<hex-signature>",
                    device::DEVICE_SCHEME
                ),
            }),
            "unknown",
            "enrolment reads no artifact, so nothing was checked.",
        ),
        // One refusal for unknown, expired and already-claimed. Distinguishing them would tell
        // someone holding a guessed code whether they guessed a real one.
        Err(EnrolError::CodeNotUsable) => ArchiveResponse::error(
            status::FORBIDDEN,
            "code_not_usable",
            "that enrolment code is not usable: it is unknown, expired, or already claimed. Ask an \
             operator for a new one.",
        ),
        // The device id holding this key is NOT named. Enrolment proves possession of a code, never
        // of the private half of the key presented — so naming the id would hand whoever ran this
        // the identity to ask an operator to revoke. The code is not consumed either, so the
        // operator who hit this can retry with a fresh keypair.
        Err(EnrolError::KeyAlreadyEnrolled) => ArchiveResponse::error(
            status::FORBIDDEN,
            "device_key_already_enrolled",
            "that device key is already enrolled at this archive. A key may name exactly one \
             device, because revocation is by device id and a key with two ids could not be \
             withdrawn. Enrol a fresh keypair: on the device, `warrantor archive enrol … \
             --replace` mints one. Your enrolment code was not spent.",
        ),
        Err(EnrolError::Store(_)) => ArchiveResponse::error(
            status::UNAVAILABLE,
            "store_unavailable",
            "the archive could not reach its store, so no device was enrolled.",
        ),
    }
}

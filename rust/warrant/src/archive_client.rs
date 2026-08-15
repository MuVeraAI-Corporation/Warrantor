//! Filing evidence with an evidence archive: the request descriptor both halves share, and the
//! client that speaks it.
//!
//! # Why this lives in `warrantor-warrant` and not in `warrantor-archive`
//!
//! `warrantor-archive` (RFC W2) shipped complete and with **no clients**. Nothing outside that
//! crate could produce a `Warrantor-Device` `Authorization` header, so the documented `curl` route
//! for filing an artifact could not actually be performed by anybody, and `submitted_by_device` —
//! the whole point of device pairing — had never named a person outside a unit test.
//!
//! The obvious fix, calling `warrantor_archive::device::sign_request` from the local agent, is the
//! one thing that crate's `Cargo.toml` forbids in writing: **the dependency edge runs archive →
//! warrant, never the reverse**, because `warrantor-archive` pulls `postgres` and therefore tokio.
//! Inverting it would put an async runtime and a database client into a program whose entire point
//! is to run on a developer's laptop with nothing installed.
//!
//! So the signing half of the wire contract lives *here*, in the crate the archive already depends
//! on, and `warrantor_archive::device` re-exports it. There is exactly **one** `request_descriptor`
//! and exactly one `sha256_hex` behind it. A client that reimplemented the descriptor would not
//! fail silently — signatures would simply be refused — but it would be a second definition of a
//! wire contract, and two definitions drift on the next change.
//!
//! This module is **not** the `warrantor-archive` crate and holds none of its policy: no freshness
//! window, no nonce-length cap, no body cap, no store. Those are the server's to decide and to
//! refuse on, and a client carrying its own copy of a server's limit is a client that will one day
//! disagree with the server about what is allowed.
//!
//! # The contract, stated once
//!
//! ```text
//! Authorization: Warrantor-Device <device_id>.<timestamp>.<nonce>.<hex-signature>
//! ```
//!
//! The signature is Ed25519 over [`dsse_pae`](warrantor_evidence::dsse_pae) of
//! [`request_descriptor`], which pins the method, the path, the device, the nonce, the timestamp
//! and a SHA-256 of the body. A signature therefore cannot be lifted onto another route, another
//! body or another device.
//!
//! **The query string is not covered.** The archive rebuilds the signed path from validated path
//! segments only, so a signature says nothing about `?foo=bar`. No archive route reads a query
//! parameter today, which makes this latent rather than exploitable — but a future route that did
//! would be reachable with a lifted signature, and it is written down here rather than relied on
//! silently.
//!
//! # What this client refuses to do
//!
//! * **It never re-serialises evidence.** [`push`] takes a `&[u8]` it does not parse. An exported
//!   bundle is written with `to_vec_pretty`; a round trip through `serde_json` would produce
//!   different bytes, so the archive would content-address a file that is not the one on the
//!   operator's disk — and both copies would still "verify", which is the worst shape a failure
//!   can take.
//! * **It checks the digest the archive returns against the digest it sent, at runtime.** A
//!   disagreement is [`ArchiveClientError::DigestDisagreement`] and the push fails. This is a
//!   refusal and not a test assertion on purpose: the whole value of a content-addressed archive is
//!   that the address names the bytes, and a client that printed a success line under a digest it
//!   did not compute would be certifying something it never checked.
//! * **It checks fetched bytes against the digest that was asked for**, for the same reason and in
//!   the same place.
//! * **It holds one key per device id, and refuses to blur the two.** Enrolment mints a *fresh*
//!   keypair and refuses to run over an existing [`ArchiveConfig`] without `--replace`, and every
//!   signed request checks the key on disk against [`ArchiveConfig::device_public_key`] first. The
//!   failure this prevents is the one that defeats revocation: enrolling the same key twice leaves
//!   two device ids sharing one credential, so revoking the id you can name withdraws nothing —
//!   the same key keeps filing and reading under the id you cannot. The archive enforces the other
//!   half (`EnrolError::KeyAlreadyEnrolled`, and a unique index on `device.public_key`), because a
//!   rule only a client keeps is not a rule.
//! * **It never prints or returns a verdict.** A 200 from `POST /v1/evidence` means *these bytes
//!   are held*. The archive deliberately stores artifacts whose ingest check is `failed` or
//!   `unknown`, so [`Filed::ingest_check`] is carried verbatim under a name that cannot be read as
//!   one. Verification happens only where it always happened: `warrantor verify <file> --issuer
//!   <hex>`, in Rust, on the reader's own machine.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use warrantor_evidence::dsse_pae;

use crate::report::sha256_hex;

/// The scheme token in the `Authorization` header.
pub const DEVICE_SCHEME: &str = "Warrantor-Device";

/// The descriptor's own format line. Present so a later change to the signed shape is detectable
/// rather than silently misverified.
pub const REQUEST_DESCRIPTOR_FORMAT: &str = "warrantor.archive-request/1";

/// Wire format of an archive success or refusal body.
///
/// Present from the first release for the reason every other format constant in this repository is:
/// the day the shape changes, a client parsing the old one must fail loudly rather than silently
/// read a field that moved. This client does exactly that — see [`ArchiveClientError::Unreadable`].
pub const ARCHIVE_RESPONSE_FORMAT: &str = "warrantor.archive-response/1";

/// Wire format of `<root>/archive.json`, the local pairing record.
pub const ARCHIVE_CONFIG_FORMAT: &str = "warrantor.archive-pairing/1";

/// The file, under the warrant store's root, that records which archive this device is paired with.
///
/// Named beside `backends.json`, which is the existing precedent for a small local config file
/// under the same root.
pub const ARCHIVE_CONFIG_FILE: &str = "archive.json";

/// Is this a device id an archive could have issued?
///
/// Validated, not sanitised: a hostile string is refused rather than transformed into a different
/// string that is then used. Shared because both halves need the same answer — the archive parses
/// it off an `Authorization` header, and this client checks what it is about to sign under and what
/// an archive handed back at enrolment.
#[must_use]
pub fn is_device_id(value: &str) -> bool {
    let Some(body) = value.strip_prefix("dev_") else {
        return false;
    };
    !body.is_empty() && body.len() <= 64 && body.chars().all(|c| c.is_ascii_alphanumeric())
}

/// The exact string a device signature covers.
///
/// Every field that could otherwise be swapped is in here. Without the method and path a signature
/// over a `GET` could be replayed as a `POST`; without the body digest a valid signature could be
/// lifted onto different bytes; without the device id one device's signature could be presented
/// under another's name; without the nonce and timestamp the whole request replays forever.
#[must_use]
pub fn request_descriptor(
    method: &str,
    path: &str,
    device_id: &str,
    nonce: &str,
    timestamp: u64,
    body: &[u8],
) -> String {
    format!(
        "{REQUEST_DESCRIPTOR_FORMAT}\n{method}\n{path}\n{device_id}\n{nonce}\n{timestamp}\n{}",
        sha256_hex(body)
    )
}

/// The bytes a device actually signs: DSSE PAE over the descriptor.
///
/// Reusing [`dsse_pae`] rather than signing the descriptor directly is not decoration. PAE is
/// length-prefixed, so a descriptor field containing a newline cannot shift the meaning of the
/// fields after it, and it is the encoding every other signature in this repository is taken over —
/// so there is one convention here rather than two.
#[must_use]
pub fn signing_input(descriptor: &str) -> Vec<u8> {
    dsse_pae(descriptor)
}

/// Sign a request as a device. The one place an `Authorization` header for an archive is built.
#[must_use]
pub fn sign_request(
    key: &SigningKey,
    method: &str,
    path: &str,
    device_id: &str,
    nonce: &str,
    timestamp: u64,
    body: &[u8],
) -> String {
    use ed25519_dalek::Signer;
    let descriptor = request_descriptor(method, path, device_id, nonce, timestamp, body);
    let signature = key.sign(&signing_input(&descriptor));
    format!(
        "{DEVICE_SCHEME} {device_id}.{timestamp}.{nonce}.{}",
        hex::encode(signature.to_bytes())
    )
}

/// Mint a nonce from the system CSPRNG.
///
/// Never a counter and never the timestamp. A nonce is refused permanently the second time an
/// archive sees it under the same device, so a client that derived one from state it could lose —
/// or from a clock — would eventually lock itself out of filing anything.
///
/// 32 hex characters: inside every archive's nonce charset and length cap by a wide margin, so the
/// client does not need a copy of the server's limit to satisfy it.
///
/// # Errors
/// [`ArchiveClientError::Randomness`] if the operating system will not supply randomness. Refusing
/// is the only safe answer; a weaker source produces something shaped like a nonce that is not one.
pub fn mint_nonce() -> Result<String, ArchiveClientError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| ArchiveClientError::Randomness(format!("the system CSPRNG refused: {e}")))?;
    Ok(hex::encode(bytes))
}

// ── transport ─────────────────────────────────────────────────────────────────────────

/// One answer off the wire, unjudged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveAnswer {
    /// The HTTP status.
    pub status: u16,
    /// The body bytes, exactly as they arrived.
    pub body: Vec<u8>,
}

/// How this library reaches an archive, with no socket in it.
///
/// The same shape [`crate::guard::GuardTransport`] and
/// [`crate::adapters::github::GitHubTransport`] take: the real client is built in the binary, so
/// the library stays testable without a network and this crate acquires no HTTP server of its own.
///
/// **One method, not `get` and `post`.** The method string is inside the signed descriptor, so a
/// transport that chose the verb itself could send a request under a signature taken over a
/// different one. Here the caller names the method once and it is both signed and sent.
///
/// It also differs from the GitHub transport in one deliberate way: a non-2xx status is **not** an
/// `Err`. The archive's refusals carry a stable machine code and a sentence written about the
/// caller's request — `stale_request` naming both clocks, `payload_too_large`, `device_revoked` —
/// and collapsing them into "the request failed" would send an operator hunting a key problem that
/// is a clock problem. `Err` is reserved for never having got an answer at all.
pub trait ArchiveTransport {
    /// Send one request and return whatever came back.
    ///
    /// Implementations MUST send the body verbatim, MUST set `content-type: application/json` when
    /// the body is non-empty (the archive answers 415 for any other type), and MUST NOT follow
    /// redirects: a redirect would resend a signature bound to the original path.
    ///
    /// # Errors
    /// A human-readable reason, only when no answer was received.
    fn send(
        &mut self,
        method: &str,
        path: &str,
        authorization: Option<&str>,
        body: &[u8],
    ) -> Result<ArchiveAnswer, String>;
}

// ── local pairing record ──────────────────────────────────────────────────────────────

/// When evidence should be filed to the archive without an operator passing `--archive`.
///
/// A policy, not a default: `off` is what a record written before this field existed means, so a
/// machine that never asked for automatic filing never gets it. `settle` files the final report at
/// the moment the warrant's story is over — the one moment an operator will not think to type a
/// flag, because from their side they are done.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AutoFile {
    /// File nothing automatically. Today's behaviour, and what an absent field means.
    #[default]
    Off,
    /// At settle, file the final report export. A filing that fails does not undo the settle;
    /// it is queued and retried at the next settle.
    Settle,
}

/// Which archive this device is paired with, and under what name.
///
/// Written by `warrantor archive enrol` and read by everything else. It deliberately holds **no
/// key**: the private half lives in `<root>/keys/device.key` like every other key on this machine,
/// and a config file that carried one would be a config file people paste into issues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveConfig {
    /// Always [`ARCHIVE_CONFIG_FORMAT`].
    pub format: String,
    /// The archive's base URL, e.g. `http://127.0.0.1:8788`. No trailing slash.
    pub url: String,
    /// The device id this archive issued at enrolment.
    pub device_id: String,
    /// Hex of the public half of the key that was enrolled under [`Self::device_id`].
    ///
    /// A device id and a key are **one** credential, and this field is what lets that be checked
    /// locally. Without it, a `keys/device.key` that does not belong to this device id — an enrolment
    /// that died between writing the key and writing this record, a key restored from another
    /// machine's backup — produces a perfectly well-formed signature that the archive refuses with a
    /// message about signatures, sending the operator to look for a key problem instead of a pairing
    /// one. The private half is still never written here; this is the same 32 bytes the archive
    /// already holds.
    pub device_public_key: String,
    /// The label the operator gave the device when the code was minted, as the archive reported it.
    pub label: String,
    /// When the archive said the enrolment happened, epoch seconds.
    pub enrolled_at: u64,
    /// Whether settle files the final report without being asked. Absent means [`AutoFile::Off`]:
    /// records written before this field existed keep their meaning, and the format stays /1 for
    /// the same reason — an older binary reading this record ignores the field and behaves as
    /// `off`, which is the safe direction for a policy to default in.
    #[serde(default)]
    pub auto_file: AutoFile,
}

impl ArchiveConfig {
    /// Where the pairing record lives under a warrant store root.
    #[must_use]
    pub fn path(root: &Path) -> PathBuf {
        root.join(ARCHIVE_CONFIG_FILE)
    }

    /// Read the pairing record, or refuse.
    ///
    /// There is no default and no empty fallback. A missing file means this device was never
    /// enrolled anywhere, and inventing an archive URL or a device id would produce a request that
    /// fails at the far end with a message about signatures instead of one about pairing.
    ///
    /// # Errors
    /// [`ArchiveClientError::NotConfigured`] when the file is absent, or
    /// [`ArchiveClientError::Config`] when it is present and unusable.
    pub fn load(root: &Path) -> Result<Self, ArchiveClientError> {
        let path = Self::path(root);
        let body = match std::fs::read(&path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ArchiveClientError::NotConfigured(path))
            }
            Err(e) => {
                return Err(ArchiveClientError::Config(format!(
                    "read {}: {e}",
                    path.display()
                )))
            }
        };
        let config: Self = serde_json::from_slice(&body).map_err(|e| {
            ArchiveClientError::Config(format!("{} is not a pairing record: {e}", path.display()))
        })?;
        if config.format != ARCHIVE_CONFIG_FORMAT {
            return Err(ArchiveClientError::Config(format!(
                "{} declares format {:?}; this build writes and reads {ARCHIVE_CONFIG_FORMAT}",
                path.display(),
                config.format
            )));
        }
        if !is_device_id(&config.device_id) {
            return Err(ArchiveClientError::Config(format!(
                "{} names device {:?}, which is not a device id an archive could have issued",
                path.display(),
                config.device_id
            )));
        }
        parse_public_key_hex(&config.device_public_key).map_err(|e| {
            ArchiveClientError::Config(format!(
                "{} records this device's public key as {:?}, and {e}",
                path.display(),
                config.device_public_key
            ))
        })?;
        check_url(&config.url)?;
        Ok(config)
    }

    /// Read the pairing record only if there is one, distinguishing "no pairing" from "unreadable".
    ///
    /// `Ok(None)` means this machine is not paired. An unreadable record is **not** flattened into
    /// that: a file that exists and cannot be parsed still means a device was enrolled and is
    /// probably still active at the archive, and treating it as "never paired" is what would let a
    /// second enrolment quietly orphan the first.
    ///
    /// # Errors
    /// [`ArchiveClientError::Config`] when a record is present and unusable.
    pub fn read_if_present(root: &Path) -> Result<Option<Self>, ArchiveClientError> {
        match Self::load(root) {
            Ok(config) => Ok(Some(config)),
            Err(ArchiveClientError::NotConfigured(_)) => Ok(None),
            Err(other) => Err(other),
        }
    }

    /// Write the pairing record, atomically.
    ///
    /// Content goes to a temporary file and is then renamed over the target, the same way a warrant
    /// is written. A half-written pairing record is worse than none: `load` would refuse it, and the
    /// operator would be told they are not paired by a machine that is.
    ///
    /// # Errors
    /// [`ArchiveClientError::Config`] when it cannot be encoded or written.
    pub fn save(&self, root: &Path) -> Result<PathBuf, ArchiveClientError> {
        let path = Self::path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                ArchiveClientError::Config(format!("create {}: {e}", parent.display()))
            })?;
        }
        let body = serde_json::to_vec_pretty(self)
            .map_err(|e| ArchiveClientError::Config(format!("encode pairing record: {e}")))?;
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, &body).map_err(|e| {
            ArchiveClientError::Config(format!("write {}: {e}", temporary.display()))
        })?;
        std::fs::rename(&temporary, &path)
            .map_err(|e| ArchiveClientError::Config(format!("write {}: {e}", path.display())))?;
        Ok(path)
    }

    /// Refuse a key that is not the one this pairing was written for.
    ///
    /// # Errors
    /// [`ArchiveClientError::DeviceKeyMismatch`] when the key on disk is not the enrolled one.
    pub fn check_key(&self, key: &SigningKey, key_path: &Path) -> Result<(), ArchiveClientError> {
        let on_disk = hex::encode(key.verifying_key().to_bytes());
        if on_disk == self.device_public_key {
            return Ok(());
        }
        Err(ArchiveClientError::DeviceKeyMismatch(Box::new(
            DeviceKeyMismatch {
                path: key_path.to_path_buf(),
                url: self.url.clone(),
                device_id: self.device_id.clone(),
                enrolled: self.device_public_key.clone(),
                on_disk,
            },
        )))
    }
}

/// Parse the hex form of a device's public key, refusing anything that is not one.
///
/// # Errors
/// [`ArchiveClientError::Config`] saying what is wrong with it.
pub fn parse_public_key_hex(text: &str) -> Result<ed25519_dalek::VerifyingKey, ArchiveClientError> {
    let raw = hex::decode(text.trim()).map_err(|_| {
        ArchiveClientError::Config(
            "a device public key is 64 hex characters (32 bytes); that is not hex".to_string(),
        )
    })?;
    let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        ArchiveClientError::Config(format!(
            "that key is {} bytes; an Ed25519 verifying key is 32 (64 hex characters)",
            raw.len()
        ))
    })?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|e| {
        ArchiveClientError::Config(format!("that is not a valid Ed25519 verifying key: {e}"))
    })
}

/// Refuse a URL this client will not send a signed request to.
///
/// Scheme only, and no hostname resolution: what is being refused here is a typo or a `file://`,
/// not a network policy this command has no standing to make.
///
/// # Errors
/// [`ArchiveClientError::Config`] naming what is wrong with it.
pub fn check_url(url: &str) -> Result<(), ArchiveClientError> {
    if url.starts_with("http://") || url.starts_with("https://") {
        if url.ends_with('/') {
            return Err(ArchiveClientError::Config(format!(
                "{url:?} ends in a slash. Give the archive's base URL with no trailing slash, e.g. \
                 http://127.0.0.1:8788 — the path is appended verbatim and is part of what every \
                 request is signed over."
            )));
        }
        return Ok(());
    }
    Err(ArchiveClientError::Config(format!(
        "{url:?} is not an archive URL. It must begin http:// or https://."
    )))
}

// ── results ───────────────────────────────────────────────────────────────────────────

/// What the archive recorded about one filing.
///
/// Note what this type does **not** have: a field a viewer would render as a verdict. The archive's
/// door check is carried under [`Self::ingest_check`] and [`Self::ingest_reason`], with the
/// archive's own sentence about where a real answer comes from in [`Self::verify_locally`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filed {
    /// SHA-256 of the bytes that were sent — checked against the archive's answer before this
    /// value is returned. See [`ArchiveClientError::DigestDisagreement`].
    pub digest: String,
    /// `report`, `stop` or `ledger`, as the archive classified it.
    pub kind: String,
    /// The warrant the artifact names.
    pub warrant_id: String,
    /// True when the archive already held these exact bytes. Not an error: submission is idempotent
    /// on the digest, so a retry cannot create a duplicate.
    pub already_held: bool,
    /// The device the archive attributed the filing to.
    pub submitted_by_device: String,
    /// The archive's clock at the moment of filing, epoch seconds.
    pub submitted_at: u64,
    /// `ok`, `failed` or `unknown`. **Not a verdict.**
    pub ingest_check: String,
    /// The sentence behind the word, empty on a pass.
    pub ingest_reason: String,
    /// The archive's own sentence about what its opinion is worth.
    pub verify_locally: String,
}

/// One row of a warrant's listing: what the archive holds, not what it is worth.
///
/// Declared here rather than reusing `warrantor_archive::store::ArtifactSummary`, which is the same
/// shape. Depending on `warrantor-archive` from `rust/warrant` would pull `postgres` and tokio into
/// a program whose whole point is running on a laptop with nothing installed — the same reasoning
/// that moved the signing half of the wire contract in this direction rather than the other. The
/// duplication is a wire type on two sides of a wire, which is what a wire type is.
///
/// Every field is a fact the archive recorded at the door. **None of them is a verdict**, and
/// [`Self::ingest_check`] in particular is the note taken when the bytes arrived, not an opinion
/// about them now — a listing reads no artifact body, so nothing here checked a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// SHA-256 hex. Also the address [`fetch`] takes.
    pub digest: String,
    /// `report`, `stop` or `ledger`, as the archive classified it at ingest.
    pub kind: String,
    /// The warrant this artifact is about.
    pub warrant_id: String,
    /// The archive's clock when it was filed, epoch seconds.
    pub submitted_at: u64,
    /// The device that filed it.
    pub submitted_by_device: String,
    /// `ok`, `failed` or `unknown` — the door's note. **Not a verdict.**
    pub ingest_check: String,
}

/// What the archive holds about one warrant, and what it says that listing is worth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holdings {
    /// The warrant asked about, echoed back.
    pub warrant_id: String,
    /// The rows, newest first, exactly as the archive ordered them.
    pub artifacts: Vec<Held>,
    /// The archive's own sentence about why a listing establishes nothing about the bytes.
    pub verify_locally: String,
}

/// Custody totals across everything the paired archive holds — the fleet-level view no single
/// machine can answer, because no single machine holds the filings.
///
/// Every number is an aggregate of **custody records** — what arrived, from which devices, about
/// which warrants, when. No artifact body was read and no signature was checked for anything
/// counted here, and [`Self::verify_locally`] carries the archive's own sentence saying so. The
/// decision-maker's question this serves ("what did our agents file, this quarter, from where")
/// is answered by what reached custody, which is a question an evidence relay can answer
/// honestly — never "what did our agents do", which is a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetSummary {
    /// Artifacts held, all warrants.
    pub artifacts: u64,
    /// Distinct warrants with anything held.
    pub warrants: u64,
    /// Distinct devices that ever filed.
    pub devices: u64,
    /// The earliest filing the archive recorded, `None` when it holds nothing. An empty archive
    /// is a real answer, kept distinct from an unreadable store — which is a refusal, as ever.
    pub first_filed_at: Option<u64>,
    /// The latest filing the archive recorded.
    pub last_filed_at: Option<u64>,
    /// Artifacts per kind, kind word → count.
    pub by_kind: std::collections::BTreeMap<String, u64>,
    /// Artifacts per device, device id → count.
    pub by_device: std::collections::BTreeMap<String, u64>,
    /// The archive's own sentence about why a summary establishes nothing about the bytes.
    pub verify_locally: String,
}

/// What the archive recorded about one enrolment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    /// The device id the archive minted. This is what future requests are signed under.
    pub device_id: String,
    /// The label the operator gave when the code was minted.
    pub label: String,
    /// The archive's clock at enrolment, epoch seconds.
    pub enrolled_at: u64,
}

/// The pairing record and the device key on disk name different keys.
///
/// Its own type, boxed inside [`ArchiveClientError::DeviceKeyMismatch`], because five inline
/// fields made that the largest variant and an enum costs its largest variant everywhere.
///
/// The message is the point of the type. What the archive can say about this is "bad signature",
/// which sends an operator to look for a signing problem — and there isn't one. The signature is
/// perfectly valid; it is made by a key that is not the one this device id was enrolled with. Only
/// the client holds both halves of that comparison, so only the client can say which it is.
#[derive(Debug, Error, PartialEq, Eq)]
#[error(
    "this machine's pairing record and its device key disagree, so nothing here can sign as \
     {device_id}: {path} holds the key {on_disk}, and the record for {url} was written for \
     {enrolled}. That is a pairing that was never completed or a key from somewhere else — not \
     a signature problem, which is all the archive would have been able to tell you. Enrol \
     again with a new one-time code:\n  warrantor archive enrol --url {url} --code <code> \
     --replace"
)]
pub struct DeviceKeyMismatch {
    /// Where the key was read from.
    pub path: PathBuf,
    /// The archive the pairing record names.
    pub url: String,
    /// The device the pairing record names.
    pub device_id: String,
    /// The public key the pairing record was written for.
    pub enrolled: String,
    /// The public half of the key actually on disk.
    pub on_disk: String,
}

/// Everything that can go wrong talking to an archive.
///
/// Every variant is a refusal and every message is written for the operator who will read it at
/// three in the afternoon with a failing pipeline. In particular a clock problem says so, because
/// an operator told only "authentication failed" goes hunting a key problem.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArchiveClientError {
    /// The system CSPRNG refused.
    #[error("{0}")]
    Randomness(String),
    /// No pairing record on this machine.
    #[error(
        "this device is not paired with an evidence archive: {0} does not exist. Pair it first:\n  \
         warrantor-archive enrol --label \"<this machine>\"   (on the archive host, prints a \
         one-time code)\n  warrantor archive enrol --url <archive-url> --code <that code>"
    )]
    NotConfigured(PathBuf),
    /// The pairing record, or a URL, is unusable.
    #[error("{0}")]
    Config(String),
    /// This machine is already paired, and enrolling again would orphan that pairing.
    ///
    /// The refusal exists because the damage is silent and one-way. A second enrolment mints a
    /// **second** device id at the archive while the first row stays active, and overwrites the only
    /// local record of the first id — and `warrantor-archive revoke` takes a device id. The operator
    /// would be left with a live device nobody on this machine can name.
    #[error(
        "this machine is already paired: {path} exists and {describes}. Enrolling again would mint \
         a SECOND device at the archive while the first stays active, and overwrite the only local \
         record of it — revocation is by device id, so that device would become unnameable from \
         here. Withdraw the old one first, then say so explicitly:\n  warrantor-archive revoke \
         --device <the id above>   (on the archive host)\n  warrantor archive enrol --url <url> \
         --code <code> --replace"
    )]
    AlreadyPaired {
        /// The pairing record that is in the way.
        path: PathBuf,
        /// What is known about the existing pairing, phrased for the message.
        describes: String,
    },
    /// The device key on disk is not the key this pairing record was written for.
    ///
    /// Boxed. Five fields inline made this variant 128 bytes, and an enum is as large as its
    /// largest variant — so every `Result<_, ArchiveClientError>` in this crate paid for it, on
    /// the success path too. `clippy::result_large_err` is what said so, across fourteen
    /// signatures. The allocation is on the error path only, which is the cold one.
    #[error(transparent)]
    DeviceKeyMismatch(Box<DeviceKeyMismatch>),
    /// A device key was expected on disk and was not there.
    #[error(
        "this device is paired with {url} as {device_id}, but its signing key is gone: {path} does \
         not exist. A device key is NOT created on demand here — one that was never enrolled \
         anywhere is not a credential, it is a file. Enrol again to pair a fresh key:\n  \
         warrantor archive enrol --url {url} --code <a new one-time code>"
    )]
    NoDeviceKey {
        /// Where the key was expected.
        path: PathBuf,
        /// The archive the pairing record names.
        url: String,
        /// The device the pairing record names.
        device_id: String,
    },
    /// No answer at all.
    #[error("the archive at {url} could not be reached: {reason}")]
    Transport {
        /// The archive that was addressed.
        url: String,
        /// What the transport said.
        reason: String,
    },
    /// The archive answered, and refused.
    #[error("the archive refused this request — HTTP {status} {code}: {message}")]
    Refused {
        /// The HTTP status.
        status: u16,
        /// The archive's stable machine code, e.g. `stale_request`.
        code: String,
        /// The archive's own sentence about the refusal.
        message: String,
    },
    /// The archive answered with something this build cannot read.
    #[error(
        "the archive answered HTTP {status} with a body this client cannot read as \
         {ARCHIVE_RESPONSE_FORMAT}: {reason}. Nothing is assumed about what it did with the \
         submission."
    )]
    Unreadable {
        /// The HTTP status that came with it.
        status: u16,
        /// What was wrong with the body.
        reason: String,
    },
    /// The digest the archive named is not the digest of the bytes involved.
    #[error(
        "DIGEST DISAGREEMENT — refusing to report this as filed. {what} was {expected}, and the \
         archive named {returned}. A content-addressed archive whose address does not name the \
         bytes is not holding the file you have, and both copies would still verify against their \
         own signatures, so this cannot be reported as a success."
    )]
    DigestDisagreement {
        /// Which digest disagreed, phrased for the message.
        what: String,
        /// What this client computed.
        expected: String,
        /// What the archive said.
        returned: String,
    },
}

// ── the three operations ──────────────────────────────────────────────────────────────

/// Enrol this device against a one-time code, returning the identity the archive minted.
///
/// This is the one unauthenticated request in the protocol: a device that is enrolling has no key
/// on file yet, so it presents the code instead. The private half of the keypair never leaves this
/// machine — only [`VerifyingKey`](ed25519_dalek::VerifyingKey) bytes are sent.
///
/// # Errors
/// [`ArchiveClientError`]: the transport failed, the archive refused (a used, expired or unknown
/// code is one `code_not_usable`, deliberately indistinguishable), or the answer was unreadable or
/// named something that is not a device id.
pub fn enrol<T: ArchiveTransport>(
    transport: &mut T,
    url: &str,
    code: &str,
    public_key: &ed25519_dalek::VerifyingKey,
) -> Result<Enrolled, ArchiveClientError> {
    check_url(url)?;
    let body = serde_json::json!({
        "code": code.trim(),
        "public_key": hex::encode(public_key.to_bytes()),
    });
    let body = serde_json::to_vec(&body)
        .map_err(|e| ArchiveClientError::Config(format!("encode enrolment: {e}")))?;
    let answer = transport
        .send("POST", "/v1/devices/enrol", None, &body)
        .map_err(|reason| ArchiveClientError::Transport {
            url: url.to_string(),
            reason,
        })?;
    let data = json_data(&answer)?;
    let device_id = string_field(&answer, &data, "device_id")?;
    if !is_device_id(&device_id) {
        return Err(ArchiveClientError::Unreadable {
            status: answer.status,
            reason: format!(
                "it enrolled this device as {device_id:?}, which is not a device id shaped like \
                 one an archive issues"
            ),
        });
    }
    Ok(Enrolled {
        device_id,
        label: string_field(&answer, &data, "label")?,
        enrolled_at: u64_field(&answer, &data, "enrolled_at")?,
    })
}

/// File one evidence file, verbatim.
///
/// `bytes` are sent exactly as given: not parsed, not re-serialised, not pretty-printed. The digest
/// the descriptor is signed over and the digest checked against the archive's answer are the same
/// SHA-256 of the same buffer, computed once.
///
/// # Errors
/// [`ArchiveClientError`]. In particular [`ArchiveClientError::DigestDisagreement`] when the
/// archive names a digest other than the one these bytes hash to — a refusal, not a warning,
/// because there is no reading of that disagreement under which the filing succeeded.
pub fn push<T: ArchiveTransport>(
    transport: &mut T,
    config: &ArchiveConfig,
    key: &SigningKey,
    bytes: &[u8],
    now: u64,
) -> Result<Filed, ArchiveClientError> {
    if bytes.is_empty() {
        return Err(ArchiveClientError::Config(
            "refusing to file an empty file: there is no evidence in zero bytes".to_string(),
        ));
    }
    let digest = sha256_hex(bytes);
    let path = "/v1/evidence";
    let nonce = mint_nonce()?;
    let authorization = sign_request(key, "POST", path, &config.device_id, &nonce, now, bytes);
    let answer = transport
        .send("POST", path, Some(&authorization), bytes)
        .map_err(|reason| ArchiveClientError::Transport {
            url: config.url.clone(),
            reason,
        })?;
    let data = json_data(&answer)?;
    let returned = string_field(&answer, &data, "digest")?;
    // A runtime refusal, not a test. This client computed `digest` to build the signature, so the
    // comparison is free; and an archive that filed bytes under a different address is not holding
    // the operator's file, however cheerful its 200 was.
    if returned != digest {
        return Err(ArchiveClientError::DigestDisagreement {
            what: "the SHA-256 of the bytes sent".to_string(),
            expected: digest,
            returned,
        });
    }
    let not_a_verdict = answer_body(&answer)?;
    let not_a_verdict = not_a_verdict.get("not_a_verdict").cloned().ok_or_else(|| {
        ArchiveClientError::Unreadable {
            status: answer.status,
            reason: "it carried no not_a_verdict block, so what the door made of this submission \
                     is unknown"
                .to_string(),
        }
    })?;
    Ok(Filed {
        digest,
        kind: string_field(&answer, &data, "kind")?,
        warrant_id: string_field(&answer, &data, "warrant_id")?,
        already_held: data
            .get("already_held")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| ArchiveClientError::Unreadable {
                status: answer.status,
                reason: "data.already_held was missing or not a boolean".to_string(),
            })?,
        submitted_by_device: string_field(&answer, &data, "submitted_by_device")?,
        submitted_at: u64_field(&answer, &data, "submitted_at")?,
        ingest_check: string_field(&answer, &not_a_verdict, "ingest_check")?,
        ingest_reason: not_a_verdict
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string(),
        verify_locally: string_field(&answer, &not_a_verdict, "verify_locally")?,
    })
}

/// Custody totals across everything the paired archive holds.
///
/// The fleet-level question — "what did our agents file, from where, when" — is one no machine
/// can answer about itself, because filings live at the archive. This asks the one component
/// that holds them, and renders what it can answer honestly: an account of custody records,
/// aggregated. It is never an account of what the agents *did*; the archive's own
/// `not_a_verdict` sentence travels with the numbers.
///
/// An archive holding nothing summarises as zero with `None` timestamps — a real answer, this
/// archive has received no filings — kept distinct from a store the archive could not read,
/// which is a refusal ([`ArchiveClientError::Refused`] on `store_unavailable`) exactly as a
/// listing is.
///
/// # Errors
/// [`ArchiveClientError`] when the request cannot be signed or sent, the archive refuses, or the
/// answer is not one this client can read.
pub fn summary<T: ArchiveTransport>(
    transport: &mut T,
    config: &ArchiveConfig,
    key: &SigningKey,
    now: u64,
) -> Result<FleetSummary, ArchiveClientError> {
    let path = "/v1/summary".to_string();
    let nonce = mint_nonce()?;
    let authorization = sign_request(key, "GET", &path, &config.device_id, &nonce, now, &[]);
    let answer = transport
        .send("GET", &path, Some(&authorization), &[])
        .map_err(|reason| ArchiveClientError::Transport {
            url: config.url.clone(),
            reason,
        })?;
    let data = json_data(&answer)?;
    let not_a_verdict = answer_body(&answer)?
        .get("not_a_verdict")
        .cloned()
        .ok_or_else(|| ArchiveClientError::Unreadable {
            status: answer.status,
            reason: "it carried no not_a_verdict block, so what the archive says a summary is \
                     worth is unknown"
                .to_string(),
        })?;
    let optional_at = |name: &str| -> Result<Option<u64>, ArchiveClientError> {
        match data.get(name) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(value) => value
                .as_u64()
                .map(Some)
                .ok_or_else(|| ArchiveClientError::Unreadable {
                    status: answer.status,
                    reason: format!("{name} was present and not a whole number"),
                }),
        }
    };
    let counts =
        |name: &str| -> Result<std::collections::BTreeMap<String, u64>, ArchiveClientError> {
            let map = data
                .get(name)
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| ArchiveClientError::Unreadable {
                    status: answer.status,
                    reason: format!("data.{name} was missing or not an object"),
                })?;
            let mut out = std::collections::BTreeMap::new();
            for (key, value) in map {
                let count = value
                    .as_u64()
                    .ok_or_else(|| ArchiveClientError::Unreadable {
                        status: answer.status,
                        reason: format!("data.{name}.{key} was not a whole number"),
                    })?;
                out.insert(key.clone(), count);
            }
            Ok(out)
        };
    Ok(FleetSummary {
        artifacts: u64_field(&answer, &data, "artifacts")?,
        warrants: u64_field(&answer, &data, "warrants")?,
        devices: u64_field(&answer, &data, "devices")?,
        first_filed_at: optional_at("first_filed_at")?,
        last_filed_at: optional_at("last_filed_at")?,
        by_kind: counts("by_kind")?,
        by_device: counts("by_device")?,
        verify_locally: string_field(&answer, &not_a_verdict, "verify_locally")?,
    })
}

/// Fetch one artifact's bytes back out, by digest.
///
/// Reading is authenticated too — every archive route except health and enrolment is — so this is
/// the other half of the loop that no `curl` could perform. The returned bytes are the bytes that
/// were filed, and this function checks that before returning them: an archive is a relay, and a
/// relay that hands back something other than what was asked for must not be believed silently.
///
/// What comes back is still unverified evidence. Check it where evidence is always checked:
/// `warrantor verify <file> --issuer <hex>`.
///
/// # Errors
/// [`ArchiveClientError`], including [`ArchiveClientError::DigestDisagreement`] when the bytes
/// returned are not the bytes that digest names.
pub fn fetch<T: ArchiveTransport>(
    transport: &mut T,
    config: &ArchiveConfig,
    key: &SigningKey,
    digest: &str,
    now: u64,
) -> Result<Vec<u8>, ArchiveClientError> {
    let digest = digest.trim().to_ascii_lowercase();
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ArchiveClientError::Config(format!(
            "{digest:?} is not an artifact address. An artifact is addressed by the 64-character \
             SHA-256 hex digest `warrantor archive push` printed when it was filed."
        )));
    }
    let path = format!("/v1/evidence/{digest}");
    let nonce = mint_nonce()?;
    let authorization = sign_request(key, "GET", &path, &config.device_id, &nonce, now, &[]);
    let answer = transport
        .send("GET", &path, Some(&authorization), &[])
        .map_err(|reason| ArchiveClientError::Transport {
            url: config.url.clone(),
            reason,
        })?;
    if answer.status != 200 {
        return Err(refusal(&answer));
    }
    let returned = sha256_hex(&answer.body);
    if returned != digest {
        return Err(ArchiveClientError::DigestDisagreement {
            what: "the artifact asked for".to_string(),
            expected: digest,
            returned,
        });
    }
    Ok(answer.body)
}

/// What the archive holds about one warrant.
///
/// The verb that makes the other two auditable. `push` prints a digest once; if that scrollback is
/// gone, `fetch` cannot help, because `fetch` takes the digest you no longer have. Filing evidence
/// you can never enumerate is a write-only archive, which is indistinguishable from a directory
/// nobody reads.
///
/// Authenticated like every route but health and enrolment, so this is not something `curl` could
/// do either.
///
/// **A listing is not verification, and this function is careful not to imply it is.** The archive
/// reads no artifact body to produce these rows, so no signature was checked for any of them;
/// `ingest_check` is the note taken at the door when the bytes arrived. Nothing here is a substitute
/// for `warrantor archive fetch <digest> --out <path>` followed by `warrantor verify <path>`, and
/// [`Holdings::verify_locally`] carries the archive's own sentence saying so.
///
/// An empty list is returned as an empty list. It is a real answer — this archive holds nothing
/// about that warrant — and it is reported distinctly from a store the archive could not read,
/// which is a refusal ([`ArchiveClientError::Refused`] on the archive's `store_unavailable`). The
/// archive is deliberate about that distinction on its side; discarding it here would put the two
/// back together.
///
/// # Errors
/// [`ArchiveClientError`] when the request cannot be signed or sent, the archive refuses, or the
/// answer is not one this client can read.
pub fn list<T: ArchiveTransport>(
    transport: &mut T,
    config: &ArchiveConfig,
    key: &SigningKey,
    warrant_id: &str,
    now: u64,
) -> Result<Holdings, ArchiveClientError> {
    let warrant_id = warrant_id.trim();
    if warrant_id.is_empty() || warrant_id.contains('/') {
        return Err(ArchiveClientError::Config(format!(
            "{warrant_id:?} is not a warrant id. It is the id `warrantor grant` printed and \
             `warrantor list` shows, and it cannot contain a path separator."
        )));
    }
    let path = format!("/v1/warrants/{warrant_id}/evidence");
    let nonce = mint_nonce()?;
    let authorization = sign_request(key, "GET", &path, &config.device_id, &nonce, now, &[]);
    let answer = transport
        .send("GET", &path, Some(&authorization), &[])
        .map_err(|reason| ArchiveClientError::Transport {
            url: config.url.clone(),
            reason,
        })?;
    let data = json_data(&answer)?;
    // `not_a_verdict` is a sibling of `data` in the envelope, not inside it — the same read `push`
    // makes. An earlier draft of this function looked for it inside `data`, where it never is on
    // the wire, and every well-formed 200 would have failed as unreadable; written from the wire
    // format rather than from `push`'s variable names, which is what the tests hold it to.
    let not_a_verdict = answer_body(&answer)?
        .get("not_a_verdict")
        .cloned()
        .ok_or_else(|| ArchiveClientError::Unreadable {
            status: answer.status,
            reason: "it carried no not_a_verdict block, so what the archive says a listing is \
                     worth is unknown"
                .to_string(),
        })?;

    let rows = data
        .get("artifacts")
        .and_then(|value| value.as_array().cloned())
        .ok_or_else(|| ArchiveClientError::Unreadable {
            status: answer.status,
            reason: "data.artifacts was missing or not an array".to_string(),
        })?;
    let mut artifacts = Vec::with_capacity(rows.len());
    for row in rows {
        artifacts.push(Held {
            digest: string_field(&answer, &row, "digest")?,
            kind: string_field(&answer, &row, "kind")?,
            warrant_id: string_field(&answer, &row, "warrant_id")?,
            submitted_at: u64_field(&answer, &row, "submitted_at")?,
            submitted_by_device: string_field(&answer, &row, "submitted_by_device")?,
            ingest_check: string_field(&answer, &row, "ingest_check")?,
        });
    }
    // The archive echoes the id it was asked about. A runtime check rather than a test, like the
    // digest check in `push`: an answer about a different warrant is not the answer to the question
    // that was asked, and rendering it under the requested id would file the operator's next
    // `fetch` under someone else's evidence.
    let echoed = string_field(&answer, &data, "warrant_id")?;
    if echoed != warrant_id {
        return Err(ArchiveClientError::Unreadable {
            status: answer.status,
            reason: format!(
                "the listing came back about {echoed:?}, not the {warrant_id:?} that was asked \
                 about, so it is not an answer to the question"
            ),
        });
    }
    Ok(Holdings {
        warrant_id: echoed,
        artifacts,
        verify_locally: string_field(&answer, &not_a_verdict, "verify_locally")?,
    })
}

// ── reading an answer ─────────────────────────────────────────────────────────────────

/// The parsed body of a JSON answer, with the format line checked.
fn answer_body(answer: &ArchiveAnswer) -> Result<serde_json::Value, ArchiveClientError> {
    let value: serde_json::Value =
        serde_json::from_slice(&answer.body).map_err(|e| ArchiveClientError::Unreadable {
            status: answer.status,
            reason: format!("it is not JSON: {e}"),
        })?;
    match value.get("format").and_then(serde_json::Value::as_str) {
        Some(ARCHIVE_RESPONSE_FORMAT) => Ok(value),
        Some(other) => Err(ArchiveClientError::Unreadable {
            status: answer.status,
            reason: format!("it declares format {other:?}"),
        }),
        None => Err(ArchiveClientError::Unreadable {
            status: answer.status,
            reason: "it carries no format field".to_string(),
        }),
    }
}

/// The `data` object of a successful answer, or the archive's own refusal.
fn json_data(answer: &ArchiveAnswer) -> Result<serde_json::Value, ArchiveClientError> {
    if answer.status != 200 {
        return Err(refusal(answer));
    }
    let body = answer_body(answer)?;
    body.get("data")
        .cloned()
        .ok_or_else(|| ArchiveClientError::Unreadable {
            status: answer.status,
            reason: "a 200 carried no data object".to_string(),
        })
}

/// Turn a non-200 into the archive's own words, or say plainly that it did not use its own words.
fn refusal(answer: &ArchiveAnswer) -> ArchiveClientError {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(&answer.body).ok();
    let error = parsed.as_ref().and_then(|body| body.get("error").cloned());
    match error {
        Some(error) => ArchiveClientError::Refused {
            status: answer.status,
            code: error
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unnamed")
                .to_string(),
            message: error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("the archive gave no reason")
                .to_string(),
        },
        None => ArchiveClientError::Unreadable {
            status: answer.status,
            reason: "it is not an archive refusal body".to_string(),
        },
    }
}

fn string_field(
    answer: &ArchiveAnswer,
    object: &serde_json::Value,
    name: &str,
) -> Result<String, ArchiveClientError> {
    object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ArchiveClientError::Unreadable {
            status: answer.status,
            reason: format!("{name} was missing or not a string"),
        })
}

fn u64_field(
    answer: &ArchiveAnswer,
    object: &serde_json::Value,
    name: &str,
) -> Result<u64, ArchiveClientError> {
    object
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| ArchiveClientError::Unreadable {
            status: answer.status,
            reason: format!("{name} was missing or not a whole number"),
        })
}

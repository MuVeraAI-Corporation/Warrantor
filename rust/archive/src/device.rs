//! Device pairing: what finally lets the audit trail name a person.
//!
//! # The gap this closes, and the one it does not
//!
//! `warrantor serve` authenticates with a single unscoped bearer token per process. Everyone
//! holding it is the same principal, so the trail can say *someone with the token did this* and
//! nothing more — W1 delivery gap 2.2, and `serve.rs` names it as the right next fix in its own
//! comments.
//!
//! Here an operator enrols a device with a one-time code; the device generates an Ed25519 keypair,
//! keeps the private half, and **signs every request**. The archive stores only the public half.
//! `submitted_by_device` on every artifact is therefore a name, not a role.
//!
//! What that attributes is the **submission** of an artifact and the **read** of one. It does not
//! attribute the settle: settle happens on a laptop, under the local agent's settle key, and may
//! never touch this server at all. Saying "who settled this" is now answerable would be
//! over-claiming, and would get gap 2.2 marked closed when it is half closed.
//!
//! # The header, and why it is the one that already exists
//!
//! Everything travels in `Authorization`, which `parse_request` already captures:
//!
//! ```text
//! Authorization: Warrantor-Device <device_id>.<timestamp>.<nonce>.<hex-signature>
//! ```
//!
//! Using the existing header means no change to header capture and no second place a header can be
//! parsed. The signature covers [`dsse_pae`](warrantor_evidence::dsse_pae) over a canonical
//! descriptor that pins the method, the path, the device, the nonce, the timestamp and a digest of
//! the body — so a signature cannot be lifted onto a different route, a different body, or a
//! different device.
//!
//! # Freshness, and the contrast with the notary's gate
//!
//! [`warrantor_warrant::report`] states plainly that its freshness gate sees an empty seen-nonce set
//! and therefore cannot detect a replay. That is an honest limitation of a report generated in one
//! process from one clock read. **This surface actually has a replay store** — a unique index on
//! `(device_id, nonce)` — so the claim can be made here and it is made no more widely than that: a
//! request is refused if its nonce was seen before under the same device, or if its timestamp falls
//! outside [`FRESHNESS_WINDOW_SECONDS`] of the server's clock.
//!
//! # Where the signed descriptor lives, and why it is not here
//!
//! [`DEVICE_SCHEME`], [`REQUEST_DESCRIPTOR_FORMAT`], [`is_device_id`], [`request_descriptor`],
//! [`signing_input`] and [`sign_request`] are **re-exports from
//! [`warrantor_warrant::archive_client`]**, not definitions. They are the half of this contract a
//! client needs, and the local agent cannot reach into this crate for them: `Cargo.toml` states
//! that the dependency edge runs archive → warrant and never the reverse, because this crate pulls
//! `postgres` and therefore tokio, and the agent's whole point is to run on a laptop with nothing
//! installed. Putting the descriptor in the crate both halves already share is the only shape in
//! which there is exactly **one** definition of what a device signature covers. A second copy would
//! not fail silently — signatures would be refused — but it would drift on the next change to the
//! descriptor, and then two builds would disagree about a wire format while both looked correct.
//!
//! What stays here is what only a server does: parsing a presented credential, the freshness
//! window, the nonce cap, enrolment codes, minting device ids, and [`authenticate`].

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use crate::sha256_hex;
use crate::store::{ArchiveStore, NonceOutcome, StoreError};

pub use warrantor_warrant::archive_client::{
    is_device_id, request_descriptor, sign_request, signing_input, DEVICE_SCHEME,
    REQUEST_DESCRIPTOR_FORMAT,
};

/// How far a request's timestamp may sit from the server's clock, in seconds, in either direction.
///
/// Both directions, deliberately. A window that only bounded the past would accept a request
/// timestamped a year ahead, which is a replay that has not happened yet: it becomes valid the
/// moment the nonce store is lost or rebuilt.
pub const FRESHNESS_WINDOW_SECONDS: u64 = 300;

/// How long a one-time enrolment code stays claimable, in seconds.
///
/// Fifteen minutes: long enough to walk a code to another machine, short enough that a code left in
/// a chat log is not a standing invitation.
pub const ENROLMENT_CODE_LIFETIME_SECONDS: u64 = 15 * 60;

/// Longest nonce accepted, in characters. Bounded before it reaches a store.
pub const MAX_NONCE_LEN: usize = 128;

/// A freshly minted one-time enrolment code.
///
/// The plaintext exists only in this value and is printed once. Only [`EnrolmentCode::digest`] is
/// ever stored, so a stolen database yields no usable code — the same shape as a password digest and
/// for the same reason.
#[derive(Debug, Clone)]
pub struct EnrolmentCode {
    code: String,
    digest: String,
}

impl EnrolmentCode {
    /// Mint 32 bytes from the system CSPRNG.
    ///
    /// # Errors
    /// [`DeviceError::Randomness`] if the operating system will not supply randomness. Refusing is
    /// the only safe response, exactly as [`warrantor_warrant::serve::SessionToken::mint`] refuses:
    /// a fallback to a weaker source produces something shaped like a secret that is not one.
    pub fn mint() -> Result<Self, DeviceError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| DeviceError::Randomness(format!("the system CSPRNG refused: {e}")))?;
        let code = hex::encode(bytes);
        let digest = sha256_hex(code.as_bytes());
        Ok(Self { code, digest })
    }

    /// The code, to be shown to a human exactly once.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The digest, which is the only part that is stored.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The digest of a code a device presented.
    #[must_use]
    pub fn digest_of(presented: &str) -> String {
        sha256_hex(presented.trim().as_bytes())
    }
}

/// Mint a device identifier.
///
/// Random rather than derived from the public key. A device id appears in every audit row, and an
/// id that is a function of the key would make rotating a compromised key rewrite the identity of
/// everything that device ever filed.
///
/// # Errors
/// [`DeviceError::Randomness`] if the system CSPRNG refuses.
pub fn mint_device_id() -> Result<String, DeviceError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| DeviceError::Randomness(format!("the system CSPRNG refused: {e}")))?;
    Ok(format!("dev_{}", hex::encode(bytes)))
}

/// Everything that can go wrong authenticating a device request.
///
/// Every variant is a refusal, and the messages are written about the caller's request rather than
/// about this archive's contents: a denial that explains itself describes the shape of the
/// boundary, which is the notary's rule and applies here too.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeviceError {
    /// The system CSPRNG refused.
    #[error("{0}")]
    Randomness(String),
    /// No `Authorization` header, or one this archive does not speak.
    #[error("this request carried no Warrantor-Device authorization")]
    NoCredential,
    /// The credential is present but not four dot-separated parts.
    #[error(
        "a device credential is <device_id>.<timestamp>.<nonce>.<hex-signature>, four \
         dot-separated parts"
    )]
    Malformed,
    /// The timestamp is outside the freshness window.
    #[error(
        "this request is timestamped {presented} and the archive's clock reads {now}; the \
         accepted window is {window} seconds either way"
    )]
    Stale {
        /// The timestamp the request carried.
        presented: u64,
        /// The archive's clock.
        now: u64,
        /// The window, in seconds.
        window: u64,
    },
    /// The nonce was seen before under this device.
    #[error("this request replays a nonce this device has already used")]
    Replay,
    /// No such device, or one that was never enrolled.
    #[error("this request names a device this archive does not know")]
    UnknownDevice,
    /// The device was enrolled and then revoked.
    #[error("this device was revoked and can no longer submit or read")]
    Revoked,
    /// The signature does not check out against the device's enrolled key.
    #[error("the signature does not verify against this device's enrolled key")]
    BadSignature,
    /// The store could not answer.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// A credential lifted off the `Authorization` header, before anything about it is believed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCredential {
    /// Who claims to be sending this.
    pub device_id: String,
    /// When they claim to have sent it, epoch seconds.
    pub timestamp: u64,
    /// A value this device has not used before.
    pub nonce: String,
    /// Hex Ed25519 signature over [`request_descriptor`].
    pub signature: String,
}

/// Parse an `Authorization` header value. Nothing here is trusted; it is only shaped.
///
/// # Errors
/// [`DeviceError::NoCredential`] or [`DeviceError::Malformed`].
pub fn parse_credential(header: Option<&str>) -> Result<DeviceCredential, DeviceError> {
    let value = header.ok_or(DeviceError::NoCredential)?;
    let rest = value
        .strip_prefix(DEVICE_SCHEME)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or(DeviceError::NoCredential)?;
    let parts: Vec<&str> = rest.trim().split('.').collect();
    let [device_id, timestamp, nonce, signature] = parts.as_slice() else {
        return Err(DeviceError::Malformed);
    };
    if !is_device_id(device_id) {
        return Err(DeviceError::Malformed);
    }
    let Ok(timestamp) = timestamp.parse::<u64>() else {
        return Err(DeviceError::Malformed);
    };
    // Bounded and character-checked before it can reach a query parameter or a unique index.
    if nonce.is_empty()
        || nonce.len() > MAX_NONCE_LEN
        || !nonce
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(DeviceError::Malformed);
    }
    Ok(DeviceCredential {
        device_id: (*device_id).to_string(),
        timestamp,
        nonce: (*nonce).to_string(),
        signature: (*signature).to_string(),
    })
}

/// Authenticate one request against the store.
///
/// The order is the point, and it mirrors `handle` in `serve.rs`: everything cheap and everything
/// that reveals nothing runs first, and the nonce is only spent once the request is otherwise
/// worth spending it on. Specifically:
///
/// 1. the credential parses;
/// 2. the timestamp is inside the window (a stale request must not consume a nonce, or an attacker
///    could burn a victim's future nonces by replaying old ones);
/// 3. the device is known;
/// 4. the signature verifies against that device's enrolled key;
/// 5. the device has not been revoked;
/// 6. **and only then** the nonce is recorded, which is what makes it single-use.
///
/// Recording last means a request that fails an earlier check leaves no trace in the replay store,
/// so the store's size is a function of accepted requests rather than of attacker traffic.
///
/// **Revocation is checked after the signature, not before, and the order is the whole of a
/// property `http.rs` claims.** Checked first, an unauthenticated caller signing with a key they
/// invented got [`DeviceError::Revoked`] for a device id that exists and [`DeviceError::
/// UnknownDevice`] for one that does not — and those two are served as *different* error codes
/// (`device_revoked` versus `unauthorized`), so the route answered "does this device id exist?" to
/// anyone who asked. Checked after `verify_strict`, only someone holding the device's own private
/// key can tell the two apart, which is the person who is entitled to know their device was
/// revoked. A revoked device still spends no nonce: this check precedes the recording.
///
/// # Errors
/// The [`DeviceError`] naming the first check that failed.
pub fn authenticate<S: ArchiveStore>(
    store: &mut S,
    credential: &DeviceCredential,
    method: &str,
    path: &str,
    body: &[u8],
    now: u64,
) -> Result<crate::store::Device, DeviceError> {
    let skew = credential.timestamp.abs_diff(now);
    if skew > FRESHNESS_WINDOW_SECONDS {
        return Err(DeviceError::Stale {
            presented: credential.timestamp,
            now,
            window: FRESHNESS_WINDOW_SECONDS,
        });
    }

    let device = store
        .device(&credential.device_id)?
        .ok_or(DeviceError::UnknownDevice)?;

    let key = parse_public_key(&device.public_key)?;
    let signature = parse_signature(&credential.signature)?;
    let descriptor = request_descriptor(
        method,
        path,
        &credential.device_id,
        &credential.nonce,
        credential.timestamp,
        body,
    );
    key.verify_strict(&signing_input(&descriptor), &signature)
        .map_err(|_| DeviceError::BadSignature)?;

    // Only now, with the signature checked, is it safe to say something about *this device* rather
    // than about this request. See the ordering note on this function.
    if !device.active() {
        return Err(DeviceError::Revoked);
    }

    match store.remember_nonce(&credential.device_id, &credential.nonce, now)? {
        NonceOutcome::Fresh => Ok(device),
        NonceOutcome::Replay => Err(DeviceError::Replay),
    }
}

/// Parse a hex Ed25519 verifying key.
///
/// # Errors
/// [`DeviceError::BadSignature`] — deliberately, rather than a distinct "this device's stored key
/// is malformed". A device whose enrolled key cannot be parsed cannot have signed anything, and
/// telling a caller that the *archive's* row is broken hands them information about the archive's
/// internals in exchange for nothing.
pub fn parse_public_key(hex_key: &str) -> Result<VerifyingKey, DeviceError> {
    let raw = hex::decode(hex_key).map_err(|_| DeviceError::BadSignature)?;
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| DeviceError::BadSignature)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| DeviceError::BadSignature)
}

fn parse_signature(hex_signature: &str) -> Result<Signature, DeviceError> {
    let raw = hex::decode(hex_signature).map_err(|_| DeviceError::BadSignature)?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| DeviceError::BadSignature)?;
    Ok(Signature::from_bytes(&bytes))
}

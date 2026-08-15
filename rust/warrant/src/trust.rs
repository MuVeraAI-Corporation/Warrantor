//! Names for issuer keys, pinned locally by the person who verified them out of band.
//!
//! `warrantor verify --issuer <hex>` asks an operator to paste a 64-character key — usually from
//! the same place the evidence file came from, which verifies nothing. This module is the honest
//! alternative for a machine with no directory infrastructure: a **local, pinned** directory,
//! `trusted/issuers.json` under the store root, mapping a name a human chose to a key they
//! checked out of band, at a moment they chose.
//!
//! # The trust model, stated rather than implied
//!
//! **Trust on first use, at pinning, by a human.** Pinning is the only moment trust enters the
//! system, and it is deliberate: `warrantor issuer add ana <hex>` records *this person decided
//! this name means this key, now*. Verification against a name never acquires trust; it looks up
//! what was already decided. The verify output says which of the two happened — a name resolved
//! from the pinned directory, or a key pasted onto the command line — because those are different
//! claims and a reader is entitled to know which one backs the verdict.
//!
//! **There is no network, on purpose.** A directory that hands out keys over the network is a new
//! trust root — whoever serves it decides what every name means — and adding one casually would
//! contradict the thesis this whole platform is built on. Nothing here fetches anything. A signed
//! or shared directory is a separate design decision that has not been made, and the refusal an
//! unknown name gets says "pin it" rather than "look it up".
//!
//! **A pinned key never changes silently.** Re-pinning a name to a *different* key is the single
//! most sensitive operation a trust store has — it is exactly what an attacker who could not
//! forge a signature wants instead. So it refuses by default, naming both keys and the moment
//! the old one was pinned, and requires an explicit replace that prints what changed.
//!
//! # Why the file is not signed
//!
//! The file lives beside the issuer and settle keys it protects the meaning of, in a store the
//! operator already must control. An attacker who can rewrite it can equally rewrite
//! `keys/issuer.key` and forge evidence outright; a signature inside the store would add a key
//! to protect and protect nothing that is not already protected by the store's own boundary.
//! That reasoning is recorded here because "why isn't the trust file itself signed" is the first
//! question a security reviewer asks, and "we thought about it" should be visible.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

/// The format line of the trusted-issuers record.
pub const TRUST_FORMAT: &str = "warrantor.trusted-issuers/1";

/// A name a human chose, bound to a key they checked out of band.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedIssuer {
    /// Hex of the Ed25519 verifying key. 64 characters, as `--issuer` takes.
    pub key: String,
    /// When the pin was made, epoch seconds. Printed at verification time so a reader can ask
    /// whether they still trust a pin that old.
    pub pinned_at: u64,
    /// Free text, set by whoever pinned: where the key came from, how it was checked. Never
    /// rendered as anything but prose.
    #[serde(default)]
    pub note: String,
}

/// The directory: every name this machine trusts, in one file, in name order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Directory {
    /// Always [`TRUST_FORMAT`].
    pub format: String,
    /// Name → pin. A `BTreeMap` so the file is byte-stable for the same contents, and `issuer
    /// list` reads in name order without a sort that could drift from the file's.
    pub issuers: BTreeMap<String, PinnedIssuer>,
}

/// Where the trusted-issuers record lives under a store root.
#[must_use]
pub fn directory_path(root: &Path) -> PathBuf {
    root.join("trusted").join("issuers.json")
}

/// What pinning a name did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinOutcome {
    /// The name was new; the key is now pinned under it.
    Pinned,
    /// The name was already pinned to this same key. Not an error — re-running a setup script
    /// must not be a failure — and not a change either.
    AlreadyPinned,
    /// The name was pinned to a different key, and this call refused. The operator is told both
    /// keys and when the old pin was made; the only way forward is an explicit replace.
    RefusedDifferentKey {
        /// The key already pinned under this name.
        existing: String,
        /// When that pin was made, epoch seconds.
        pinned_at: u64,
    },
}

impl Directory {
    /// The empty directory, for a machine that has pinned nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            format: TRUST_FORMAT.to_string(),
            issuers: BTreeMap::new(),
        }
    }

    /// Read the directory.
    ///
    /// An absent file is an empty directory — the normal state of a machine that has never
    /// pinned anything, and the state every command must render distinctly from a file that
    /// exists and will not parse. The latter is an error: a reader that silently treated an
    /// unreadable trust file as "trust nothing" would turn corruption into a denial of named
    /// verification, and one that treated it as "trust anything" would be worse.
    ///
    /// # Errors
    /// [`String`] naming the file and the reason when the record exists and cannot be read, or
    /// declares a format this build does not speak.
    pub fn load(root: &Path) -> Result<Self, String> {
        let path = directory_path(root);
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(Self::empty());
        };
        let directory: Directory = serde_json::from_slice(&bytes)
            .map_err(|e| format!("{} cannot be read: {e}", path.display()))?;
        if directory.format != TRUST_FORMAT {
            return Err(format!(
                "{} declares format {:?}, and this build reads only {TRUST_FORMAT}. Nothing is \
                 guessed at across formats.",
                path.display(),
                directory.format
            ));
        }
        for (name, pin) in &directory.issuers {
            if parse_key(&pin.key).is_err() {
                return Err(format!(
                    "{} pins {name:?} to {:?}, which is not an Ed25519 verifying key. The \
                     directory is refused rather than read around that entry.",
                    path.display(),
                    pin.key
                ));
            }
        }
        Ok(directory)
    }

    /// Write the directory, atomically, so a crash mid-write can never leave half a trust file.
    ///
    /// # Errors
    /// [`String`] when the directory cannot be created or the file cannot be written.
    pub fn save(&self, root: &Path) -> Result<PathBuf, String> {
        let path = directory_path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        let body =
            serde_json::to_vec_pretty(self).map_err(|e| format!("encode the directory: {e}"))?;
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, &body)
            .map_err(|e| format!("write {}: {e}", temporary.display()))?;
        std::fs::rename(&temporary, &path).map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(path)
    }

    /// Resolve a name to its pinned key, or `None` when this machine has never pinned that name.
    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<VerifyingKey> {
        self.issuers
            .get(name)
            .and_then(|pin| parse_key(&pin.key).ok())
    }

    /// Pin a name, refusing to change a pin that already exists under a different key.
    ///
    /// # Errors
    /// [`String`] when the directory cannot be written. A refusal to re-pin is an [`Ok`]
    /// [`PinOutcome::RefusedDifferentKey`] — it is an answer, not an I/O failure.
    pub fn pin(
        &mut self,
        name: &str,
        key: &VerifyingKey,
        now: u64,
        note: &str,
    ) -> Result<PinOutcome, String> {
        let hex_key = hex::encode(key.to_bytes());
        if let Some(existing) = self.issuers.get(name) {
            if existing.key == hex_key {
                return Ok(PinOutcome::AlreadyPinned);
            }
            return Ok(PinOutcome::RefusedDifferentKey {
                existing: existing.key.clone(),
                pinned_at: existing.pinned_at,
            });
        }
        self.issuers.insert(
            name.to_string(),
            PinnedIssuer {
                key: hex_key,
                pinned_at: now,
                note: note.to_string(),
            },
        );
        Ok(PinOutcome::Pinned)
    }

    /// Replace a pin that [`Self::pin`] refused to change, recording that it was replaced.
    ///
    /// The caller is expected to have printed what [`PinOutcome::RefusedDifferentKey`] knew;
    /// this records the new moment, so the next reader sees when this name last changed meaning.
    ///
    /// # Errors
    /// [`String`] when the name is not pinned (replacing nothing is `remove` + `add`, not this)
    /// or the directory cannot be written.
    pub fn replace(
        &mut self,
        name: &str,
        key: &VerifyingKey,
        now: u64,
        note: &str,
    ) -> Result<(), String> {
        let Some(existing) = self.issuers.get_mut(name) else {
            return Err(format!(
                "{name:?} is not pinned, so there is nothing to replace. Pin it fresh instead: \
                 warrantor issuer add {name} <hex>"
            ));
        };
        *existing = PinnedIssuer {
            key: hex::encode(key.to_bytes()),
            pinned_at: now,
            note: note.to_string(),
        };
        Ok(())
    }

    /// Remove a pin. The caller says what that costs; this only does it.
    ///
    /// # Errors
    /// [`String`] when the name is not pinned.
    pub fn unpin(&mut self, name: &str) -> Result<PinnedIssuer, String> {
        self.issuers.remove(name).ok_or_else(|| {
            format!(
                "{name:?} is not pinned. warrantor issuer list shows every name this machine \
                 trusts."
            )
        })
    }
}

/// Parse a 64-hex-character Ed25519 verifying key.
///
/// # Errors
/// [`String`] explaining what a verifying key is, phrased about the text given.
pub fn parse_key(text: &str) -> Result<VerifyingKey, String> {
    let raw = hex::decode(text.trim())
        .map_err(|_| format!("{text:?} is not hex. An issuer key is 64 hex characters."))?;
    let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
        format!(
            "that key is {} bytes; an Ed25519 verifying key is 32 (64 hex characters).",
            raw.len()
        )
    })?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("that key is not an Ed25519 key: {e}"))
}

/// Is this a name a pin can carry?
///
/// Letters, digits, `-`, `_` and `.`, up to 32 of them. The 32-character cap is what makes a
/// name and a key unconfusable — a key is exactly 64 hex characters, so nothing a pin can be
/// named can look like one, and `verify --issuer <text>` never has to depend on resolution
/// order to decide which kind it was given.
///
/// # Errors
/// [`String`] naming the rule the name broke.
pub fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 32 {
        return Err(format!(
            "{name:?} is not a name. A name is 1 to 32 characters — and never 64, so that a \
             name can never be mistaken for the key it names."
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "{name:?} is not a name. A name is letters, digits, `-`, `_` and `.` — the \
             characters a shell will not reinterpret."
        ));
    }
    Ok(())
}

/// Is this text a raw key rather than a name — 64 hex characters?
#[must_use]
pub fn looks_like_a_key(text: &str) -> bool {
    text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit())
}

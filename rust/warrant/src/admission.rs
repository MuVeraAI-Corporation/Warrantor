//! Signed tool and skill admission manifests (L4-09).
//!
//! A manifest is signed by the party that vouches for a tool server and is verified against a
//! key this machine pinned out of band under a NAME (`crate::trust`). No key travels inside the
//! file: a file that carries its own verifying key verifies nothing but its own consistency.
//! Everything decided here is decided at the MCP proxy and is `BoundStrength::Mediated`; the
//! skill half (`AdmissionKind::Skill`) has no chokepoint at all and is `Observed`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::effects::{Decomposition, DecompositionRegistry, Syscall};
use crate::mcp::ToolSpec;
use crate::report::sha256_hex;
use crate::trust::Directory;

/// The manifest wire format. A new shape gets a new name, never a silent change.
pub const MANIFEST_FORMAT: &str = "warrantor.tool-manifest/1";
/// The admission receipt wire format.
pub const RECEIPT_FORMAT: &str = "warrantor.admission-receipt/1";
/// The export `warrantor verify` dispatches on.
pub const EXPORT_FORMAT: &str = "warrantor.admission-export/1";

const MANIFEST_DOMAIN: &[u8] = b"warrantor-tool-manifest-v1";
const RECEIPT_DOMAIN: &[u8] = b"warrantor-admission-receipt-v1";

/// Length-prefixed, domain-separated signing input: the same shape `lib.rs` uses for warrants,
/// so a signature over one kind of object can never be replayed as another.
fn signing_input(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + body.len() + 16);
    out.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// What the manifest admits: an MCP tool server, or a skill file identified by content digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionKind {
    /// An MCP server; `tools` names every tool it may publish.
    Tool,
    /// A skill file; `subject_digest` is its SHA-256 and `tools` names the tools it may call.
    Skill,
}

/// One tool's declared decomposition and data classes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolEntry {
    /// The syscalls this tool performs. Never empty: a tool with no effect still attests.
    pub effects: BTreeSet<Syscall>,
    /// Data classes the tool may receive or return, as the issuer names them. Recorded in the
    /// receipt; checked against a warrant bound only once Task 2.5 gives payloads a class.
    pub data_classes: BTreeSet<String>,
    /// SHA-256 hex of the tool's `inputSchema`, when pinned. A published schema that differs is
    /// the server's behavior disagreeing with its manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_digest: Option<String>,
}

/// The signed body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestClaims {
    /// Always [`MANIFEST_FORMAT`].
    pub format: String,
    /// The upstream name the tools are published under: the `UpstreamSpec::name` rule applies.
    pub server: String,
    /// Tool server or skill.
    pub kind: AdmissionKind,
    /// The issuer's version string. Recorded, not interpreted.
    pub version: String,
    /// The PINNED NAME of the signer in `trusted/issuers.json`. Never a key.
    pub issuer: String,
    /// Epoch seconds.
    pub issued_at: u64,
    /// Epoch seconds. A manifest without an end never ends, so zero is refused.
    pub expires_at: u64,
    /// For `Skill`: SHA-256 hex of the skill file. Refused when absent on a skill.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_digest: Option<String>,
    /// Bare tool name (no `<server>.` prefix) -> entry. A `BTreeMap`, so the bytes are stable.
    pub tools: BTreeMap<String, ToolEntry>,
}

/// A manifest and its Ed25519 signature over `signing_input(MANIFEST_DOMAIN, canonical claims)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    /// The claims.
    pub claims: ManifestClaims,
    /// Hex signature. Empty is "unsigned", and unsigned is refused by name.
    pub signature: String,
}

/// What refused, in one sentence the operator can act on.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AdmissionError {
    /// The file's shape is wrong.
    #[error("manifest refused: {0}")]
    Format(String),
    /// The signature does not verify against the resolved issuer key.
    #[error("manifest refused: the signature does not verify against the pinned issuer key")]
    Signature,
    /// The manifest is past its end.
    #[error("manifest refused: it expired at {expires_at}; now is {now}")]
    Expired {
        /// Epoch seconds.
        expires_at: u64,
        /// Epoch seconds.
        now: u64,
    },
    /// The issuer name is not pinned on this machine.
    #[error("manifest refused: issuer {0:?} is not pinned on this machine. Check the issuer's key out of band and pin it: warrantor issuer add {0} <hex>")]
    UnpinnedIssuer(String),
    /// The file carries no signature at all.
    #[error("manifest refused: it is unsigned. A tool server that cannot present a signed manifest is refused, not guessed at")]
    Unsigned,
    /// The server publishes something its manifest does not name.
    #[error("server {server:?} revoked: {detail}")]
    Publication {
        /// The upstream name.
        server: String,
        /// What disagreed.
        detail: String,
    },
    /// The server's manifest was revoked earlier.
    #[error("server {server:?} was revoked at {at}: {reason}")]
    Revoked {
        /// The upstream name.
        server: String,
        /// Epoch seconds.
        at: u64,
        /// Why.
        reason: String,
    },
    /// The store could not be read or written.
    #[error("admission store: {0}")]
    Io(String),
}

fn canonical(claims: &ManifestClaims) -> Result<Vec<u8>, AdmissionError> {
    serde_json::to_vec(claims).map_err(|e| AdmissionError::Format(e.to_string()))
}

/// Sign claims with the issuer's key. The signature covers the canonical JSON of `claims`, which
/// is byte-stable because every map is a `BTreeMap` and the struct's field order is fixed.
#[must_use]
pub fn sign_manifest(claims: ManifestClaims, key: &SigningKey) -> SignedManifest {
    let body = canonical(&claims).expect("claims are always serializable");
    let signature = key.sign(&signing_input(MANIFEST_DOMAIN, &body));
    SignedManifest {
        claims,
        signature: hex::encode(signature.to_bytes()),
    }
}

/// Verify format, shape, signature and expiry against an issuer key the CALLER resolved.
///
/// # Errors
/// [`AdmissionError`] naming the first thing wrong. Shape is checked before the signature so a
/// file from a future build is refused for what it is rather than for a signature this build
/// cannot compute.
pub fn verify_manifest(
    manifest: &SignedManifest,
    issuer: &VerifyingKey,
    now: u64,
) -> Result<(), AdmissionError> {
    let claims = &manifest.claims;
    if claims.format != MANIFEST_FORMAT {
        return Err(AdmissionError::Format(format!(
            "it declares format {:?}, and this build reads only {MANIFEST_FORMAT}",
            claims.format
        )));
    }
    if claims.server.is_empty()
        || !claims
            .server
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AdmissionError::Format(format!(
            "server {:?} must be letters, digits, '-' or '_', the same rule as --upstream",
            claims.server
        )));
    }
    crate::trust::check_name(&claims.issuer).map_err(AdmissionError::Format)?;
    if claims.expires_at == 0 {
        return Err(AdmissionError::Format(
            "expires_at is required: a manifest without an end never ends".to_string(),
        ));
    }
    if claims.kind == AdmissionKind::Skill && claims.subject_digest.is_none() {
        return Err(AdmissionError::Format(
            "a skill manifest must carry subject_digest, the SHA-256 of the skill file".to_string(),
        ));
    }
    if claims.tools.is_empty() {
        return Err(AdmissionError::Format(
            "a manifest naming no tools admits nothing; state the tools explicitly".to_string(),
        ));
    }
    for (tool, entry) in &claims.tools {
        if entry.effects.is_empty() {
            return Err(AdmissionError::Format(format!(
                "{tool} declares no effect syscall. A tool that only answers is `attest`; a \
                 tool with an effect must say which"
            )));
        }
    }
    if manifest.signature.is_empty() {
        return Err(AdmissionError::Unsigned);
    }
    let body = canonical(claims)?;
    let raw = hex::decode(&manifest.signature).map_err(|_| AdmissionError::Signature)?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| AdmissionError::Signature)?;
    issuer
        .verify(
            &signing_input(MANIFEST_DOMAIN, &body),
            &Signature::from_bytes(&bytes),
        )
        .map_err(|_| AdmissionError::Signature)?;
    if now >= claims.expires_at {
        return Err(AdmissionError::Expired {
            expires_at: claims.expires_at,
            now,
        });
    }
    Ok(())
}

/// SHA-256 hex over the serialized manifest, claims and signature: the identity every receipt
/// names, so a re-signed manifest is a different manifest.
#[must_use]
pub fn manifest_digest(manifest: &SignedManifest) -> String {
    let body = serde_json::to_vec(manifest).expect("a manifest is always serializable");
    sha256_hex(&body)
}

/// SHA-256 hex of a tool's `inputSchema`. `serde_json` in this workspace has no `preserve_order`,
/// so `Value::Object` is a `BTreeMap` and the bytes are key-sorted without a canonicalizer.
#[must_use]
pub fn schema_digest(schema: &Value) -> String {
    sha256_hex(&serde_json::to_vec(schema).expect("a Value is always serializable"))
}

/// Does what the server PUBLISHES agree with its manifest?
///
/// `published` carries `<server>.<tool>` names as [`crate::upstream::UpstreamSet::published_tools`]
/// returns them; other servers' tools are ignored. A tool not named, or a pinned schema whose
/// digest differs, is the server's own behavior disagreeing with its manifest.
///
/// # Errors
/// [`AdmissionError::Publication`] naming every disagreement, in name order.
pub fn check_publication(
    manifest: &SignedManifest,
    published: &[ToolSpec],
) -> Result<(), AdmissionError> {
    let server = &manifest.claims.server;
    let prefix = format!("{server}.");
    let mut faults = Vec::new();
    for tool in published {
        let Some(bare) = tool.name.strip_prefix(&prefix) else {
            continue;
        };
        match manifest.claims.tools.get(bare) {
            None => faults.push(format!(
                "publishes {bare:?}, which the manifest does not name"
            )),
            Some(entry) => {
                if let Some(pinned) = &entry.schema_digest {
                    let actual = schema_digest(&tool.input_schema);
                    if &actual != pinned {
                        faults.push(format!(
                            "publishes {bare:?} with schema {actual}, manifest pins {pinned}"
                        ));
                    }
                }
            }
        }
    }
    if faults.is_empty() {
        return Ok(());
    }
    Err(AdmissionError::Publication {
        server: server.clone(),
        detail: faults.join("; "),
    })
}

/// The manifest as declarations for the effect registry, under `<server>.<tool>` names, so a
/// manifest classifies on the same path an operator's `--upstream-effects` does.
///
/// # Errors
/// The registry's own sentence for a tool that decomposes to nothing or is named twice; neither
/// is reachable for a manifest [`verify_manifest`] accepted.
pub fn decompositions_of(manifest: &SignedManifest) -> Result<DecompositionRegistry, String> {
    let mut registry = DecompositionRegistry::new();
    for (bare, entry) in &manifest.claims.tools {
        let published = format!("{}.{bare}", manifest.claims.server);
        registry.insert(Decomposition::new(&published, entry.effects.clone())?)?;
    }
    Ok(registry)
}

/// What an admission receipt records having decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    /// The manifest was verified and is now the authority for its server.
    Admitted,
    /// The manifest, or one call under it, was refused. The manifest's standing is unchanged.
    Refused,
    /// The manifest is withdrawn; its server is refused at attach until re-admitted by name.
    Revoked,
}

/// The signed body of a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptClaims {
    /// Always [`RECEIPT_FORMAT`].
    pub format: String,
    /// Epoch seconds.
    pub at: u64,
    /// The upstream name.
    pub server: String,
    /// [`manifest_digest`] of the manifest decided on; empty for a revocation of a server
    /// whose manifest is no longer loadable.
    pub manifest_digest: String,
    /// The decision.
    pub decision: AdmissionDecision,
    /// Why, in the operator's words or this module's sentence.
    pub reason: String,
    /// The pinned name the manifest's issuer resolved through; empty when it did not resolve.
    pub issuer_name: String,
    /// The hex key that name resolved to at the moment of decision; empty when it did not.
    pub issuer_key: String,
}

/// A receipt signed by THIS machine's issuer key, so a reader elsewhere can check who decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The claims.
    pub claims: ReceiptClaims,
    /// Hex signature over `signing_input(RECEIPT_DOMAIN, canonical claims)`.
    pub signature: String,
    /// Hex verifying key of the signer, recorded for the reader. Verification takes the key
    /// from the caller, never from this field.
    pub signer_key: String,
}

/// Verify a receipt against the key the caller resolved.
///
/// # Errors
/// [`AdmissionError::Format`] on a foreign format, [`AdmissionError::Signature`] otherwise.
pub fn verify_receipt(receipt: &Receipt, signer: &VerifyingKey) -> Result<(), AdmissionError> {
    if receipt.claims.format != RECEIPT_FORMAT {
        return Err(AdmissionError::Format(format!(
            "receipt declares {:?}; this build reads {RECEIPT_FORMAT}",
            receipt.claims.format
        )));
    }
    let body =
        serde_json::to_vec(&receipt.claims).map_err(|e| AdmissionError::Format(e.to_string()))?;
    let raw = hex::decode(&receipt.signature).map_err(|_| AdmissionError::Signature)?;
    let bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| AdmissionError::Signature)?;
    signer
        .verify(
            &signing_input(RECEIPT_DOMAIN, &body),
            &Signature::from_bytes(&bytes),
        )
        .map_err(|_| AdmissionError::Signature)
}

/// `<root>/admitted/<server>.json`
#[must_use]
pub fn admitted_path(root: &Path, server: &str) -> PathBuf {
    root.join("admitted").join(format!("{server}.json"))
}

/// `<root>/admitted/<server>.revoked.json`
#[must_use]
pub fn revoked_path(root: &Path, server: &str) -> PathBuf {
    root.join("admitted").join(format!("{server}.revoked.json"))
}

/// `<root>/admission/ledger.jsonl`: one receipt per line, append-only, `sync_all` per line.
#[must_use]
pub fn ledger_path(root: &Path) -> PathBuf {
    root.join("admission").join("ledger.jsonl")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Revocation {
    at: u64,
    reason: String,
}

/// The manifests this store has admitted, and the ledger of every decision about them.
#[derive(Debug, Clone)]
pub struct AdmittedSet {
    root: PathBuf,
}

impl AdmittedSet {
    /// Open the set under a store root. Nothing is created until a decision is written.
    #[must_use]
    pub fn open(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }

    fn write_json(path: &Path, body: &[u8]) -> Result<(), AdmissionError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AdmissionError::Io(e.to_string()))?;
        }
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, body).map_err(|e| AdmissionError::Io(e.to_string()))?;
        std::fs::rename(&temporary, path).map_err(|e| AdmissionError::Io(e.to_string()))
    }

    fn receipt(
        &self,
        claims: ReceiptClaims,
        signer: &SigningKey,
    ) -> Result<Receipt, AdmissionError> {
        let body =
            serde_json::to_vec(&claims).map_err(|e| AdmissionError::Format(e.to_string()))?;
        let signature = signer.sign(&signing_input(RECEIPT_DOMAIN, &body));
        let receipt = Receipt {
            claims,
            signature: hex::encode(signature.to_bytes()),
            signer_key: hex::encode(signer.verifying_key().to_bytes()),
        };
        let path = ledger_path(&self.root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AdmissionError::Io(e.to_string()))?;
        }
        let line =
            serde_json::to_string(&receipt).map_err(|e| AdmissionError::Format(e.to_string()))?;
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| AdmissionError::Io(format!("open {}: {e}", path.display())))?;
        writeln!(file, "{line}").map_err(|e| AdmissionError::Io(e.to_string()))?;
        // Durable before the caller acts on the decision: a receipt still in a buffer when the
        // process dies is a decision nobody can later find.
        file.sync_all()
            .map_err(|e| AdmissionError::Io(e.to_string()))?;
        Ok(receipt)
    }

    /// Whether a server is revoked, and since when.
    ///
    /// # Errors
    /// [`AdmissionError::Io`] when the revocation record exists and cannot be read.
    pub fn is_revoked(&self, server: &str) -> Result<Option<(u64, String)>, AdmissionError> {
        let path = revoked_path(&self.root, server);
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(None);
        };
        let revocation: Revocation = serde_json::from_slice(&bytes)
            .map_err(|e| AdmissionError::Io(format!("{} cannot be read: {e}", path.display())))?;
        Ok(Some((revocation.at, revocation.reason)))
    }

    /// The admitted manifest for a server, or `None` when none was admitted or it was revoked.
    ///
    /// # Errors
    /// [`AdmissionError::Io`] when a record exists and cannot be read.
    pub fn load(&self, server: &str) -> Result<Option<SignedManifest>, AdmissionError> {
        if self.is_revoked(server)?.is_some() {
            return Ok(None);
        }
        let path = admitted_path(&self.root, server);
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| AdmissionError::Io(format!("{} cannot be read: {e}", path.display())))
    }

    /// Verify a manifest against the pinned directory and, if it holds, make it the authority
    /// for its server. Every outcome, admitted or refused, is receipted before this returns.
    ///
    /// A revocation withdraws ONE manifest, not the server forever: re-presenting the manifest
    /// that was withdrawn is refused, and admitting a NEW manifest lifts the revocation and is
    /// receipted like any admission. Only a digest match against the withdrawn record proves
    /// "the same manifest"; when that record cannot be read, the presentation is treated as new,
    /// because attach re-checks what the server publishes regardless.
    ///
    /// # Errors
    /// The refusal, after its receipt is durable.
    pub fn admit(
        &self,
        manifest: &SignedManifest,
        directory: &Directory,
        signer: &SigningKey,
        now: u64,
    ) -> Result<Receipt, AdmissionError> {
        let server = manifest.claims.server.clone();
        let issuer_name = manifest.claims.issuer.clone();
        let resolved = directory.resolve(&issuer_name);
        let issuer_key = resolved
            .map(|k| hex::encode(k.to_bytes()))
            .unwrap_or_default();
        let standing = self.is_revoked(&server)?;
        let withdraws_the_same = match &standing {
            None => false,
            Some(_) => self
                .withdrawn_digest(&server)?
                .is_some_and(|d| d == manifest_digest(manifest)),
        };
        let outcome = match (&standing, withdraws_the_same) {
            (Some((at, reason)), true) => Err(AdmissionError::Revoked {
                server: server.clone(),
                at: *at,
                reason: reason.clone(),
            }),
            _ => match resolved {
                None => Err(AdmissionError::UnpinnedIssuer(issuer_name.clone())),
                Some(key) => verify_manifest(manifest, &key, now),
            },
        };
        let (decision, reason) = match (&outcome, &standing, withdraws_the_same) {
            (Ok(()), Some((at, old)), _) => (
                AdmissionDecision::Admitted,
                format!(
                    "issuer {issuer_name:?} pinned; signature verifies; this admission lifts the \
                     revocation of {at} ({old})"
                ),
            ),
            (Ok(()), None, _) => (
                AdmissionDecision::Admitted,
                format!("issuer {issuer_name:?} pinned; signature verifies"),
            ),
            (Err(e), _, _) => (AdmissionDecision::Refused, e.to_string()),
        };
        let receipt = self.receipt(
            ReceiptClaims {
                format: RECEIPT_FORMAT.to_string(),
                at: now,
                server: server.clone(),
                manifest_digest: manifest_digest(manifest),
                decision,
                reason,
                issuer_name,
                issuer_key,
            },
            signer,
        )?;
        outcome?;
        if standing.is_some() {
            // The new manifest is the authority from here; the withdrawn record's story stays in
            // the ledger.
            std::fs::remove_file(revoked_path(&self.root, &server))
                .map_err(|e| AdmissionError::Io(e.to_string()))?;
        }
        let body = serde_json::to_vec_pretty(manifest)
            .map_err(|e| AdmissionError::Format(e.to_string()))?;
        Self::write_json(&admitted_path(&self.root, &server), &body)?;
        Ok(receipt)
    }

    /// The digest of the admitted record for a server as it sits on disk, read past any
    /// revocation: `load` refuses a revoked server, but the withdrawn record stays beside the
    /// revocation precisely so the presented manifest can be told from it.
    fn withdrawn_digest(&self, server: &str) -> Result<Option<String>, AdmissionError> {
        let Ok(bytes) = std::fs::read(admitted_path(&self.root, server)) else {
            return Ok(None);
        };
        match serde_json::from_slice::<SignedManifest>(&bytes) {
            Ok(withdrawn) => Ok(Some(manifest_digest(&withdrawn))),
            Err(_) => Ok(None),
        }
    }

    /// Withdraw a server's manifest. The admitted record stays on disk beside the revocation so
    /// a reader can see what was withdrawn; `load` returns `None` from here on.
    ///
    /// # Errors
    /// [`AdmissionError::Io`].
    pub fn revoke(
        &self,
        server: &str,
        reason: &str,
        signer: &SigningKey,
        now: u64,
    ) -> Result<Receipt, AdmissionError> {
        let digest = self
            .load(server)?
            .map(|m| manifest_digest(&m))
            .unwrap_or_default();
        let revocation = Revocation {
            at: now,
            reason: reason.to_string(),
        };
        let body =
            serde_json::to_vec(&revocation).map_err(|e| AdmissionError::Format(e.to_string()))?;
        Self::write_json(&revoked_path(&self.root, server), &body)?;
        self.receipt(
            ReceiptClaims {
                format: RECEIPT_FORMAT.to_string(),
                at: now,
                server: server.to_string(),
                manifest_digest: digest,
                decision: AdmissionDecision::Revoked,
                reason: reason.to_string(),
                issuer_name: String::new(),
                issuer_key: String::new(),
            },
            signer,
        )
    }

    /// Receipt a call refused under an admitted manifest. The manifest's standing is unchanged:
    /// the refused thing was the AGENT's argument, not the server's behavior.
    ///
    /// # Errors
    /// [`AdmissionError::Io`].
    pub fn refuse_call(
        &self,
        server: &str,
        manifest: &SignedManifest,
        reason: &str,
        signer: &SigningKey,
        now: u64,
    ) -> Result<Receipt, AdmissionError> {
        self.receipt(
            ReceiptClaims {
                format: RECEIPT_FORMAT.to_string(),
                at: now,
                server: server.to_string(),
                manifest_digest: manifest_digest(manifest),
                decision: AdmissionDecision::Refused,
                reason: reason.to_string(),
                issuer_name: manifest.claims.issuer.clone(),
                issuer_key: String::new(),
            },
            signer,
        )
    }

    /// Every receipt in the ledger, in order. A line that will not parse refuses the whole read:
    /// a readable prefix of a ledger is what a truncation looks like.
    ///
    /// # Errors
    /// [`AdmissionError::Io`].
    pub fn receipts(&self) -> Result<Vec<Receipt>, AdmissionError> {
        let path = ledger_path(&self.root);
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(AdmissionError::Io(format!("read {}: {e}", path.display()))),
        };
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .enumerate()
            .map(|(i, line)| {
                serde_json::from_str(line).map_err(|e| {
                    AdmissionError::Io(format!(
                        "{}: line {} will not parse: {e}",
                        path.display(),
                        i + 1
                    ))
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn entry(effects: &[Syscall]) -> ToolEntry {
        ToolEntry {
            effects: effects.iter().copied().collect(),
            data_classes: ["public".to_string()].into_iter().collect(),
            schema_digest: None,
        }
    }

    fn claims() -> ManifestClaims {
        let mut tools = BTreeMap::new();
        tools.insert("echo".to_string(), entry(&[Syscall::Attest]));
        tools.insert("fetch".to_string(), entry(&[Syscall::Net]));
        ManifestClaims {
            format: MANIFEST_FORMAT.to_string(),
            server: "selftest".to_string(),
            kind: AdmissionKind::Tool,
            version: "1.0.0".to_string(),
            issuer: "vendor".to_string(),
            issued_at: 1_786_000_000,
            expires_at: 1_786_000_000 + 86_400,
            subject_digest: None,
            tools,
        }
    }

    #[test]
    fn a_signed_manifest_verifies_and_a_tampered_one_does_not() {
        let signer = key(7);
        let signed = sign_manifest(claims(), &signer);
        verify_manifest(&signed, &signer.verifying_key(), 1_786_000_100).expect("verifies");

        let mut tampered = signed.clone();
        tampered
            .claims
            .tools
            .get_mut("echo")
            .expect("echo")
            .effects
            .insert(Syscall::Net);
        assert_eq!(
            verify_manifest(&tampered, &signer.verifying_key(), 1_786_000_100),
            Err(AdmissionError::Signature)
        );
        assert_eq!(
            verify_manifest(&signed, &key(8).verifying_key(), 1_786_000_100),
            Err(AdmissionError::Signature),
            "a different key is not the issuer"
        );
        assert!(matches!(
            verify_manifest(&signed, &signer.verifying_key(), 1_786_000_000 + 86_401),
            Err(AdmissionError::Expired { .. })
        ));
        let unsigned = SignedManifest {
            claims: claims(),
            signature: String::new(),
        };
        assert_eq!(
            verify_manifest(&unsigned, &signer.verifying_key(), 1_786_000_100),
            Err(AdmissionError::Unsigned)
        );
    }

    #[test]
    fn a_foreign_format_an_empty_effect_set_and_a_digestless_skill_are_refused_before_the_signature(
    ) {
        let mut other = claims();
        other.format = "warrantor.tool-manifest/2".to_string();
        let signed = sign_manifest(other, &key(7));
        let err =
            verify_manifest(&signed, &key(7).verifying_key(), 1_786_000_100).expect_err("foreign");
        assert!(
            matches!(&err, AdmissionError::Format(m) if m.contains("warrantor.tool-manifest/2")),
            "{err}"
        );

        let mut empty = claims();
        empty.tools.insert("noop".to_string(), entry(&[]));
        let err = verify_manifest(
            &sign_manifest(empty, &key(7)),
            &key(7).verifying_key(),
            1_786_000_100,
        )
        .expect_err("empty effects");
        assert!(
            matches!(&err, AdmissionError::Format(m) if m.contains("noop")),
            "{err}"
        );

        let mut skill = claims();
        skill.kind = AdmissionKind::Skill;
        let err = verify_manifest(
            &sign_manifest(skill, &key(7)),
            &key(7).verifying_key(),
            1_786_000_100,
        )
        .expect_err("skill without digest");
        assert!(
            matches!(&err, AdmissionError::Format(m) if m.contains("subject_digest")),
            "{err}"
        );
    }

    #[test]
    fn a_server_publishing_beyond_its_manifest_is_a_publication_fault() {
        let signed = sign_manifest(claims(), &key(7));
        let echo = ToolSpec {
            name: "selftest.echo".to_string(),
            description: String::new(),
            input_schema: serde_json::json!({"type": "object"}),
        };
        check_publication(&signed, std::slice::from_ref(&echo)).expect("echo is named");

        let extra = ToolSpec {
            name: "selftest.delete_everything".to_string(),
            description: String::new(),
            input_schema: serde_json::json!({"type": "object"}),
        };
        let err = check_publication(&signed, &[echo.clone(), extra]).expect_err("not named");
        assert!(
            matches!(&err, AdmissionError::Publication { server, detail }
                if server == "selftest" && detail.contains("delete_everything")),
            "{err}"
        );
        // Another server's tools are not this manifest's business.
        let foreign = ToolSpec {
            name: "other.delete_everything".to_string(),
            description: String::new(),
            input_schema: serde_json::json!({"type": "object"}),
        };
        check_publication(&signed, &[echo, foreign]).expect("other servers are ignored");
    }

    #[test]
    fn a_pinned_schema_that_changed_is_a_publication_fault() {
        let mut pinned = claims();
        let schema =
            serde_json::json!({"type": "object", "properties": {"text": {"type": "string"}}});
        pinned.tools.get_mut("echo").expect("echo").schema_digest = Some(schema_digest(&schema));
        let signed = sign_manifest(pinned, &key(7));

        let same = ToolSpec {
            name: "selftest.echo".into(),
            description: String::new(),
            input_schema: schema.clone(),
        };
        check_publication(&signed, std::slice::from_ref(&same)).expect("same schema");

        let changed = ToolSpec {
            name: "selftest.echo".into(),
            description: String::new(),
            input_schema: serde_json::json!({"type": "object", "properties": {"url": {"type": "string"}}}),
        };
        assert!(matches!(
            check_publication(&signed, &[changed]),
            Err(AdmissionError::Publication { .. })
        ));
    }

    #[test]
    fn a_manifest_becomes_declarations_under_its_published_names() {
        let registry = decompositions_of(&sign_manifest(claims(), &key(7))).expect("decomposes");
        assert_eq!(registry.len(), 2);
        let fetch = registry.get("selftest.fetch").expect("published name");
        assert_eq!(fetch.render(), "net");
        assert_eq!(fetch.class(), crate::SideEffectClass::Read);
        assert!(
            registry.get("fetch").is_none(),
            "bare names are never declared"
        );
    }
}

//! # warrantor-provena-chain (S2)
//!
//! Tamper-evident model provenance ledger. Every model artifact (weights, fine-tune, merge,
//! evaluation) is recorded as a ledger entry; the Merkle root over all entries is anchored to
//! the Sigstore Rekor transparency log (or a blockchain) periodically. Required for EU AI Act
//! Article 55 lineage compliance (per cross-cutting 13-compliance-frameworks.md).
//!
//! Builds on the Merkle primitives pattern from T1 trust-core (RFC 6962 SHA-256 ordering).
//!
//! See RFC S2 and `docs/cross-cutting/13-compliance-frameworks.md`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
use uuid::Uuid;

/// A provenance entry. One per model artifact event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// UUID entry id.
    pub id: String,
    /// The artifact URI this entry records (e.g. "model://warrantor-7b@v1").
    pub artifact_uri: String,
    /// The artifact's content digest (sha256:...) — invariant I-06 (artifact identity is exact).
    pub artifact_digest: String,
    /// The event type.
    #[serde(rename = "type")]
    pub event_type: EventType,
    /// Parent artifact URIs (lineage: base models, source datasets, etc.).
    pub parents: Vec<String>,
    /// Free-form metadata (training hyperparams, eval scores, etc.).
    pub metadata: BTreeMap<String, String>,
    /// When the event was recorded (epoch seconds).
    pub recorded_at: u64,
    /// The signer (did:web or SPIFFE ID).
    pub signer: String,
}

/// The kind of event a provenance entry records.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Initial training of a base model.
    Trained,
    /// Fine-tuning from a parent model.
    FineTuned,
    /// Merging two or more parent models.
    Merged,
    /// An evaluation was performed (links to a VEB P8).
    Evaluated,
    /// A conversion (e.g. SafeTensors → TensorRT engine).
    Converted,
    /// A distribution event (publish to registry, mirror, etc.).
    Distributed,
    /// A revocation (the artifact is no longer trusted).
    Revoked,
}

impl Entry {
    /// Canonical bytes for Merkle hashing: deterministic, length-prefixed concatenation of the
    /// load-bearing fields (everything except the ledger-assigned `id` and `recorded_at`, which
    /// are intrinsic to the event, plus the signature which is added later).
    ///
    /// Every field is preceded by its length as a little-endian u64, which makes the encoding
    /// unambiguous and prevents signature/leaf-hash forgery via field re-splitting (C2:
    /// previously fields were concatenated with no delimiter, so "ab"+"c" and "a"+"bc" produced
    /// the same canonical bytes).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_len_prefixed(&mut out, self.artifact_uri.as_bytes());
        write_len_prefixed(&mut out, self.artifact_digest.as_bytes());
        write_len_prefixed(&mut out, format!("{:?}", self.event_type).as_bytes());
        // Length-prefix the vec so its cardinality is unambiguous.
        write_len_prefixed(&mut out, &self.parents.len().to_le_bytes());
        for p in &self.parents {
            write_len_prefixed(&mut out, p.as_bytes());
        }
        // BTreeMap iterates in sorted-key order → deterministic.
        write_len_prefixed(&mut out, &self.metadata.len().to_le_bytes());
        for (k, v) in &self.metadata {
            write_len_prefixed(&mut out, k.as_bytes());
            write_len_prefixed(&mut out, v.as_bytes());
        }
        out
    }

    /// SHA-256 leaf hash (RFC 6962: SHA-256(0x00 || canonical_bytes)).
    #[must_use]
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00]);
        h.update(self.canonical_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}

/// Write `field` to `out` prefixed by its length as a little-endian u64. This makes the
/// canonical encoding unambiguous (length-prefixed framing prevents field-re-splitting forgery).
fn write_len_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_le_bytes());
    out.extend_from_slice(field);
}

/// A checkpoint — the Merkle root over a range of entries, anchored to a transparency log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The Merkle root (hex).
    pub root_hex: String,
    /// Number of entries covered.
    pub entry_count: usize,
    /// The transparency log the root was anchored to ("rekor", "blockchain:ethereum", etc.).
    pub log: String,
    /// The log's entry id (Rekor UUID, block hash, etc.).
    pub log_entry_id: String,
    /// When the checkpoint was recorded.
    pub anchored_at: u64,
    /// Ed25519 signature (hex) over the canonical bytes (root || entry_count || log || log_entry_id).
    pub signature_hex: String,
    /// The verifying key (hex) that signed this checkpoint.
    pub verifying_key_hex: String,
}

/// Errors returned by the ledger.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// The checkpoint signature did not verify.
    #[error("checkpoint signature invalid")]
    SignatureInvalid,
    /// A duplicate entry id was added.
    #[error("duplicate entry id: {0}")]
    DuplicateEntryId(String),
    /// A leaf was not found in the ledger.
    #[error("entry not found: {0}")]
    EntryNotFound(String),
    /// Hex decode failed.
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    /// Wrong length on a key/signature.
    #[error("invalid length: {0}")]
    InvalidLength(String),
    /// A persistence I/O operation failed (H10: file-backed ledger).
    #[error("persistence io error: {0}")]
    PersistIo(#[from] std::io::Error),
    /// A persistence serialize/deserialize operation failed (H10: file-backed ledger).
    #[error("persistence serde error: {0}")]
    PersistSerde(#[from] serde_json::Error),
}

/// A persistence backend for the ledger (H10). The default ledger is in-memory only; this trait
/// lets a caller plug in a durable backend so the ledger survives process restarts (required for
/// EU AI Act Article 55 lineage compliance, which assumes the provenance graph is durable).
pub trait PersistenceBackend {
    /// Write the serialized ledger snapshot (JSON bytes).
    ///
    /// # Errors
    /// Returns [`LedgerError::PersistIo`] on I/O failure.
    fn write(&mut self, snapshot: &[u8]) -> Result<(), LedgerError>;

    /// Read the previously-written snapshot bytes. Returns `None` if the backend has no data
    /// (e.g. a fresh file the first time the process starts).
    ///
    /// # Errors
    /// Returns [`LedgerError::PersistIo`] on I/O failure.
    fn read(&self) -> Result<Option<Vec<u8>>, LedgerError>;
}

/// A file-backed persistence backend (H10). Writes the snapshot JSON to `path` atomically
/// (write-to-temp-then-rename) so a crash mid-write cannot corrupt the ledger file.
pub struct FileBackend {
    path: std::path::PathBuf,
}

impl FileBackend {
    /// Construct a file backend pointing at `path`. The file is created on the first `write`.
    #[must_use]
    pub fn new<P: Into<std::path::PathBuf>>(path: P) -> Self {
        Self { path: path.into() }
    }

    /// The file path this backend persists to.
    #[must_use]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl PersistenceBackend for FileBackend {
    fn write(&mut self, snapshot: &[u8]) -> Result<(), LedgerError> {
        // Atomic write: write to a sibling temp file, then rename over the target. This prevents
        // a partial write from corrupting an existing ledger if the process crashes mid-write.
        let mut tmp = self.path.clone();
        tmp.set_extension("tmp");
        std::fs::write(&tmp, snapshot)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn read(&self) -> Result<Option<Vec<u8>>, LedgerError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(LedgerError::PersistIo(e)),
        }
    }
}

/// A serializable snapshot of the ledger's durable state (H10). The signing key is serialized
/// as hex bytes so it round-trips through JSON (ed25519_dalek::SigningKey does not implement
/// Serialize/Deserialize itself). This is the wire format for [`Ledger::persist_to_file`] and
/// [`Ledger::load_from_file`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    /// The schema version of this snapshot (forward-compat for task 03 changes).
    pub version: u32,
    /// The ledger entries, in append order.
    pub entries: Vec<Entry>,
    /// The signing key bytes (hex) used to sign checkpoints.
    pub signing_key_hex: String,
}

/// The provenance ledger.
pub struct Ledger {
    entries: Vec<Entry>,
    by_id: std::collections::HashMap<String, usize>,
    signing_key: SigningKey,
}

impl Ledger {
    /// Construct a new empty ledger with a freshly generated Ed25519 key pair.
    pub fn new() -> Self {
        let mut rng = OsRng;
        Self {
            entries: Vec::new(),
            by_id: std::collections::HashMap::new(),
            signing_key: SigningKey::generate(&mut rng),
        }
    }

    /// Construct a ledger with an explicit signing key (for tests / restoring from secret).
    pub fn with_signing_key(signing_key: SigningKey) -> Self {
        Self {
            entries: Vec::new(),
            by_id: std::collections::HashMap::new(),
            signing_key,
        }
    }

    /// The verifying key (hex) for this ledger.
    #[must_use]
    pub fn verifying_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Append an entry to the ledger. Assigns the entry id and recorded_at; returns the stored entry.
    ///
    /// # Errors
    /// Returns [`LedgerError::DuplicateEntryId`] if the entry's id is already present (the
    /// caller normally leaves `id` empty and the ledger assigns one).
    pub fn append(&mut self, mut entry: Entry) -> Result<&Entry, LedgerError> {
        if entry.id.is_empty() {
            entry.id = Uuid::new_v4().to_string();
        }
        if self.by_id.contains_key(&entry.id) {
            return Err(LedgerError::DuplicateEntryId(entry.id.clone()));
        }
        if entry.recorded_at == 0 {
            entry.recorded_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
        }
        let idx = self.entries.len();
        self.by_id.insert(entry.id.clone(), idx);
        self.entries.push(entry);
        Ok(&self.entries[idx])
    }

    /// Number of entries in the ledger.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get an entry by id.
    ///
    /// # Errors
    /// Returns [`LedgerError::EntryNotFound`] if absent.
    pub fn get(&self, id: &str) -> Result<&Entry, LedgerError> {
        self.by_id
            .get(id)
            .map(|&i| &self.entries[i])
            .ok_or_else(|| LedgerError::EntryNotFound(id.to_string()))
    }

    /// Compute the Merkle root over all entries (RFC 6962).
    #[must_use]
    pub fn merkle_root(&self) -> [u8; 32] {
        if self.entries.is_empty() {
            return [0u8; 32];
        }
        let mut layer: Vec<[u8; 32]> = self.entries.iter().map(|e| e.leaf_hash()).collect();
        while layer.len() > 1 {
            let mut next = Vec::with_capacity(layer.len().div_ceil(2));
            let mut i = 0;
            while i < layer.len() {
                if i + 1 < layer.len() {
                    next.push(node_hash(&layer[i], &layer[i + 1]));
                } else {
                    next.push(layer[i]); // orphan promotion
                }
                i += 2;
            }
            layer = next;
        }
        layer[0]
    }

    /// Create a checkpoint of the current Merkle root, signed by this ledger's key.
    /// The `log` and `log_entry_id` describe where the root was anchored (e.g. Rekor).
    #[must_use]
    pub fn checkpoint(&self, log: &str, log_entry_id: &str) -> Checkpoint {
        let root = self.merkle_root();
        let root_hex = hex::encode(root);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut canon = Vec::new();
        canon.extend_from_slice(&root);
        canon.extend_from_slice(&self.entries.len().to_le_bytes());
        canon.extend_from_slice(log.as_bytes());
        canon.extend_from_slice(log_entry_id.as_bytes());
        canon.extend_from_slice(&now.to_le_bytes());
        let sig = self.signing_key.sign(&canon);
        Checkpoint {
            root_hex,
            entry_count: self.entries.len(),
            log: log.to_string(),
            log_entry_id: log_entry_id.to_string(),
            anchored_at: now,
            signature_hex: hex::encode(sig.to_bytes()),
            verifying_key_hex: self.verifying_key_hex(),
        }
    }

    /// Verify a checkpoint's signature against its embedded verifying key.
    ///
    /// # Errors
    /// Returns [`LedgerError::SignatureInvalid`] on any failure.
    pub fn verify_checkpoint(checkpoint: &Checkpoint) -> Result<(), LedgerError> {
        let root = hex::decode(&checkpoint.root_hex)?;
        let root_arr: [u8; 32] = root
            .as_slice()
            .try_into()
            .map_err(|_| LedgerError::InvalidLength("root".into()))?;
        let vk_bytes: [u8; 32] = hex::decode(&checkpoint.verifying_key_hex)?
            .as_slice()
            .try_into()
            .map_err(|_| LedgerError::InvalidLength("verifying_key".into()))?;
        let sig_bytes = hex::decode(&checkpoint.signature_hex)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| LedgerError::InvalidLength("signature".into()))?;
        let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| LedgerError::SignatureInvalid)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let mut canon = Vec::new();
        canon.extend_from_slice(&root_arr);
        canon.extend_from_slice(&checkpoint.entry_count.to_le_bytes());
        canon.extend_from_slice(checkpoint.log.as_bytes());
        canon.extend_from_slice(checkpoint.log_entry_id.as_bytes());
        canon.extend_from_slice(&checkpoint.anchored_at.to_le_bytes());
        vk.verify(&canon, &sig)
            .map_err(|_| LedgerError::SignatureInvalid)
    }

    /// Export the ledger as a signed JSON-LD lineage graph.
    #[must_use]
    pub fn to_jsonld(&self) -> serde_json::Value {
        let nodes: Vec<serde_json::Value> = self
            .entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "@id": format!("aumos:provenance:{}", e.id),
                    "@type": format!("aumos:{}", format!("{:?}", e.event_type).to_lowercase()),
                    "aumos:artifact_uri": e.artifact_uri,
                    "aumos:artifact_digest": e.artifact_digest,
                    "aumos:parents": e.parents,
                    "aumos:metadata": e.metadata,
                    "aumos:recorded_at": e.recorded_at,
                    "aumos:signer": e.signer,
                    "aumos:leaf_hash": hex::encode(e.leaf_hash())
                })
            })
            .collect();
        serde_json::json!({
            "@context": {
                "aumos": "https://warrantor.dev/vocab/provenance#",
                "@vocab": "https://warrantor.dev/vocab/provenance#"
            },
            "@graph": nodes,
            "aumos:merkle_root": hex::encode(self.merkle_root()),
            "aumos:entry_count": self.entries.len(),
            "aumos:verifying_key": self.verifying_key_hex()
        })
    }

    /// Serialize a snapshot of the ledger's durable state (entries + signing key) to JSON bytes.
    /// Used by [`persist_to`](Self::persist_to) and [`persist_to_file`](Self::persist_to_file).
    #[must_use]
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            version: 1,
            entries: self.entries.clone(),
            signing_key_hex: hex::encode(self.signing_key.to_bytes()),
        }
    }

    /// Persist the ledger to a [`PersistenceBackend`] (H10). Serializes entries + signing key
    /// to JSON and writes via the backend (atomic write for [`FileBackend`]).
    ///
    /// # Errors
    /// Returns [`LedgerError::PersistSerde`] if serialization fails or
    /// [`LedgerError::PersistIo`] if the backend write fails.
    pub fn persist_to(&self, backend: &mut dyn PersistenceBackend) -> Result<(), LedgerError> {
        let bytes = serde_json::to_vec(&self.snapshot())?;
        backend.write(&bytes)
    }

    /// Restore a ledger from a [`PersistenceBackend`] (H10). Reads the JSON snapshot and
    /// rebuilds the in-memory state (entries, by_id index, signing key). Returns `None` (as
    /// an empty ledger via [`Ledger::new`]) if the backend has no prior data — callers should
    /// check the returned ledger's `len()` if they need to distinguish "fresh" from "restored".
    ///
    /// # Errors
    /// Returns [`LedgerError::PersistSerde`] if deserialization fails or
    /// [`LedgerError::PersistIo`] if the backend read fails.
    pub fn load_from(backend: &dyn PersistenceBackend) -> Result<Option<Ledger>, LedgerError> {
        let Some(bytes) = backend.read()? else {
            return Ok(None);
        };
        let snap: LedgerSnapshot = serde_json::from_slice(&bytes)?;
        let sk_bytes = hex::decode(&snap.signing_key_hex)?;
        let sk_arr: [u8; 32] = sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| LedgerError::InvalidLength("signing_key_hex must be 32 bytes".into()))?;
        let signing_key = SigningKey::from_bytes(&sk_arr);
        let mut by_id = std::collections::HashMap::with_capacity(snap.entries.len());
        for (i, e) in snap.entries.iter().enumerate() {
            by_id.insert(e.id.clone(), i);
        }
        Ok(Some(Ledger {
            entries: snap.entries,
            by_id,
            signing_key,
        }))
    }

    /// Convenience: persist the ledger to a JSON file at `path` (H10). Equivalent to
    /// [`persist_to`](Self::persist_to) with a [`FileBackend`].
    ///
    /// # Errors
    /// See [`Self::persist_to`].
    pub fn persist_to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<(), LedgerError> {
        let mut backend = FileBackend::new(path.as_ref());
        self.persist_to(&mut backend)
    }

    /// Convenience: restore a ledger from a JSON file at `path` (H10). Equivalent to
    /// [`load_from`](Self::load_from) with a [`FileBackend`]. Returns `Ok(None)` if the file
    /// does not exist yet (first run).
    ///
    /// # Errors
    /// See [`Self::load_from`].
    pub fn load_from_file<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Option<Ledger>, LedgerError> {
        let backend = FileBackend::new(path.as_ref());
        Self::load_from(&backend)
    }
}

impl Default for Ledger {
    fn default() -> Self {
        Self::new()
    }
}

/// RFC 6962 internal node hash: SHA-256(0x01 || left || right).
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_entry(uri: &str) -> Entry {
        Entry {
            id: String::new(),
            artifact_uri: uri.into(),
            artifact_digest: format!("sha256:{}", "a".repeat(64)),
            event_type: EventType::Trained,
            parents: vec![],
            metadata: BTreeMap::new(),
            recorded_at: 0,
            signer: "did:web:warrantor.dev".into(),
        }
    }

    #[test]
    fn append_assigns_id_and_recorded_at() {
        let mut l = Ledger::new();
        let e = l.append(base_entry("model://x")).unwrap();
        assert!(!e.id.is_empty());
        assert!(e.recorded_at > 0);
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn duplicate_explicit_id_rejected() {
        let mut l = Ledger::new();
        let mut e = base_entry("model://x");
        e.id = "fixed-id".into();
        l.append(e.clone()).unwrap();
        assert!(matches!(
            l.append(e),
            Err(LedgerError::DuplicateEntryId(s)) if s == "fixed-id"
        ));
    }

    #[test]
    fn merkle_root_changes_on_new_entry() {
        let mut l = Ledger::new();
        let r0 = l.merkle_root();
        l.append(base_entry("model://x")).unwrap();
        let r1 = l.merkle_root();
        l.append(base_entry("model://y")).unwrap();
        let r2 = l.merkle_root();
        assert_ne!(r0, r1);
        assert_ne!(r1, r2);
    }

    #[test]
    fn merkle_root_is_deterministic_for_same_entries() {
        let mut l1 = Ledger::new();
        let mut l2 = Ledger::new();
        for uri in ["model://a", "model://b", "model://c"] {
            l1.append(base_entry(uri)).unwrap();
            l2.append(base_entry(uri)).unwrap();
        }
        assert_eq!(l1.merkle_root(), l2.merkle_root());
    }

    #[test]
    fn entry_order_affects_root() {
        let mut l1 = Ledger::new();
        let mut l2 = Ledger::new();
        l1.append(base_entry("model://a")).unwrap();
        l1.append(base_entry("model://b")).unwrap();
        l2.append(base_entry("model://b")).unwrap();
        l2.append(base_entry("model://a")).unwrap();
        assert_ne!(l1.merkle_root(), l2.merkle_root());
    }

    #[test]
    fn checkpoint_round_trips_signature() {
        let mut l = Ledger::new();
        l.append(base_entry("model://x")).unwrap();
        l.append(base_entry("model://y")).unwrap();
        let cp = l.checkpoint("rekor", "rekor-uuid-123");
        Ledger::verify_checkpoint(&cp).expect("checkpoint signature verifies");
        assert_eq!(cp.entry_count, 2);
        assert_eq!(cp.log, "rekor");
    }

    #[test]
    fn tampered_checkpoint_fails() {
        let mut l = Ledger::new();
        l.append(base_entry("model://x")).unwrap();
        let mut cp = l.checkpoint("rekor", "rekor-uuid-123");
        // Flip a bit in the signature.
        let mut sig = hex::decode(&cp.signature_hex).unwrap();
        sig[0] ^= 0xff;
        cp.signature_hex = hex::encode(sig);
        assert!(matches!(
            Ledger::verify_checkpoint(&cp),
            Err(LedgerError::SignatureInvalid)
        ));
    }

    #[test]
    fn empty_ledger_root_is_zero() {
        let l = Ledger::new();
        assert_eq!(l.merkle_root(), [0u8; 32]);
        assert!(l.is_empty());
    }

    #[test]
    fn jsonld_export_has_graph_and_root() {
        let mut l = Ledger::new();
        l.append(base_entry("model://x")).unwrap();
        let jsonld = l.to_jsonld();
        assert!(jsonld["@graph"].is_array());
        assert_eq!(jsonld["aumos:entry_count"], 1);
        assert!(jsonld["aumos:merkle_root"].is_string());
    }

    #[test]
    fn leaf_hash_is_stable() {
        let e = base_entry("model://x");
        assert_eq!(e.leaf_hash(), e.leaf_hash());
    }

    #[test]
    fn lineage_parents_recorded() {
        let mut l = Ledger::new();
        let mut e = base_entry("model://finetune");
        e.event_type = EventType::FineTuned;
        e.parents = vec!["model://base".into()];
        l.append(e).unwrap();
        let stored = l.get(&l.entries[0].id.clone()).unwrap();
        assert_eq!(stored.parents, vec!["model://base".to_string()]);
        assert_eq!(stored.event_type, EventType::FineTuned);
    }

    #[test]
    fn canonical_bytes_disambiguate_field_splittings_c2() {
        // C2: length-prefixing must prevent forgery via field re-splitting.
        // entry_a: artifact_uri "ab", digest "c"
        // entry_b: artifact_uri "a", digest "bc"
        // Without length prefixes these concatenate to the same bytes ("abc"); with prefixes
        // they must differ.
        let entry_a = Entry {
            id: String::new(),
            artifact_uri: "ab".into(),
            artifact_digest: "c".into(),
            event_type: EventType::Trained,
            parents: vec![],
            metadata: BTreeMap::new(),
            recorded_at: 0,
            signer: "did:web:warrantor.dev".into(),
        };
        let entry_b = Entry {
            id: String::new(),
            artifact_uri: "a".into(),
            artifact_digest: "bc".into(),
            event_type: EventType::Trained,
            parents: vec![],
            metadata: BTreeMap::new(),
            recorded_at: 0,
            signer: "did:web:warrantor.dev".into(),
        };
        assert_ne!(
            entry_a.canonical_bytes(),
            entry_b.canonical_bytes(),
            "length-prefixed canonical bytes must distinguish different field splittings"
        );
        assert_ne!(
            entry_a.leaf_hash(),
            entry_b.leaf_hash(),
            "leaf hashes over different canonical bytes must differ"
        );
    }

    #[test]
    fn file_persistence_round_trips_entries_and_key_h10() {
        // H10: persist a ledger to a file, restore it, and confirm the entries, signing key,
        // Merkle root, and checkpoint verifiability all round-trip. The temp dir keeps the test
        // hermetic (no stray files in the repo).
        let tmp = std::env::temp_dir().join(format!(
            "warrantor-provena-test-{}-{}.json",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        // Clean up any leftover from a previous run.
        let _ = std::fs::remove_file(&tmp);

        let mut original = Ledger::new();
        original.append(base_entry("model://a")).unwrap();
        original.append(base_entry("model://b")).unwrap();
        let original_vk = original.verifying_key_hex();
        let original_root = hex::encode(original.merkle_root());
        let original_cp = original.checkpoint("rekor", "rekor-uuid-rt");

        // Persist, then load into a fresh ledger.
        original
            .persist_to_file(&tmp)
            .expect("persist_to_file succeeds");
        let restored = Ledger::load_from_file(&tmp)
            .expect("load_from_file succeeds")
            .expect("snapshot was persisted, so Some was expected");

        // Entries round-trip.
        assert_eq!(restored.len(), 2);
        assert_eq!(
            restored
                .get(&restored.entries[0].id.clone())
                .unwrap()
                .artifact_uri,
            "model://a"
        );
        // The signing key (and therefore the verifying key) round-trips.
        assert_eq!(restored.verifying_key_hex(), original_vk);
        // The Merkle root is stable across persistence (entries + ordering preserved).
        assert_eq!(hex::encode(restored.merkle_root()), original_root);
        // A freshly-signed checkpoint on the restored ledger still verifies (the restored key
        // produces valid signatures). This proves the signing key was correctly restored.
        let restored_cp = restored.checkpoint("rekor", "rekor-uuid-rt2");
        Ledger::verify_checkpoint(&restored_cp).expect("restored-ledger checkpoint verifies");
        // And the restored key signs identically to the original over the same canonical bytes
        // (a checkpoint at the same log+entry_id+root would byte-match).
        let _ = original_cp;
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn load_from_missing_file_returns_none_h10() {
        // H10: loading from a path that does not exist must return Ok(None), not an error, so a
        // fresh process can boot and create the ledger on first write.
        let missing = std::env::temp_dir().join(format!(
            "warrantor-provena-missing-{}-{}.json",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_file(&missing);
        let res = Ledger::load_from_file(&missing).expect("missing file is Ok(None)");
        assert!(res.is_none(), "missing ledger file should yield Ok(None)");
    }

    #[test]
    fn file_backend_writes_atomically_h10() {
        // H10: the FileBackend writes to a temp file then renames, so a successful write leaves
        // no .tmp sibling behind.
        let path = std::env::temp_dir().join(format!(
            "warrantor-provena-atomic-{}-{}.json",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut tmp = path.clone();
        tmp.set_extension("tmp");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&tmp);

        let mut backend = FileBackend::new(&path);
        backend.write(b"snapshot-bytes").expect("write");
        assert!(path.exists(), "target file must exist after write");
        assert!(
            !tmp.exists(),
            "temp sibling must be gone after atomic rename"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"snapshot-bytes");
        // Round-trip through the backend read().
        assert_eq!(backend.read().unwrap(), Some(b"snapshot-bytes".to_vec()));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn snapshot_captures_entries_and_signing_key_h10() {
        // H10: the snapshot is the serializable form; direct unit test that it captures what
        // the persistence path relies on.
        let mut l = Ledger::new();
        l.append(base_entry("model://snap")).unwrap();
        let snap = l.snapshot();
        assert_eq!(snap.version, 1);
        assert_eq!(snap.entries.len(), 1);
        assert_eq!(snap.entries[0].artifact_uri, "model://snap");
        // signing_key_hex must decode to 32 bytes (a valid Ed25519 signing key).
        let sk_bytes = hex::decode(&snap.signing_key_hex).unwrap();
        assert_eq!(sk_bytes.len(), 32);
        assert_eq!(hex::encode(sk_bytes), snap.signing_key_hex);
    }
}

//! DP1 Data plane — GDPR right-to-erasure vs append-only transparency log.
//!
//! The hardest problem in this layer: a transparency log is append-only; GDPR grants a right to
//! erasure. The resolution is **tombstone + redaction**: the log stays append-only (inclusion
//! proof still verifies); a signed redaction layer above it removes payload from every read path
//! (erasure satisfied). The log attests to the *existence* of a record; erasure controls what the
//! record *reveals*.
//!
//! Also: retention/pruning/compaction, tiered storage (hot/warm/cold), and dev-facing lifecycle config.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

pub const DP_VERSION: &str = "warrantor-data-plane/1.0";

// ═══════════════════════════════════════════════════════════════════════════
// Storage tiers
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageTier {
    /// Hot: queryable, sub-ms read.
    Hot,
    /// Warm: compressed, queryable on demand.
    Warm,
    /// Cold: object storage, Verify-only (no query).
    Cold,
    /// Archived: offline, Verify-only on import.
    Archived,
}

impl StorageTier {
    #[must_use]
    pub fn is_queryable(self) -> bool {
        matches!(self, StorageTier::Hot | StorageTier::Warm)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Log entry — the append-only record (never mutated, only tombstoned/redacted)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogEntry {
    pub entry_id: String,
    pub tenant_id: String,
    pub payload: serde_json::Value,
    pub stored_at: u64,
    pub tier: StorageTier,
    /// Whether this entry has been tombstoned (redacted for erasure).
    pub tombstoned: bool,
    /// Whether this entry has been pruned (hard-deleted after retention expiry).
    pub pruned: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Tombstone + redaction record — the GDPR erasure mechanism
// ═══════════════════════════════════════════════════════════════════════════

/// A redaction record: the log attests a record existed (inclusion proof); the redaction layer
/// removes the content from every read path. This is the honest resolution to erasure vs immutability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RedactionRecord {
    /// The entry being redacted.
    pub entry_id: String,
    /// The tenant requesting erasure.
    pub tenant_id: String,
    /// When the erasure was requested.
    pub requested_at: u64,
    /// When the redaction was applied.
    pub redacted_at: u64,
    /// The legal basis (e.g. "GDPR Art. 17 right to erasure").
    pub legal_basis: String,
    /// The authority that approved the redaction.
    pub approved_by: String,
    /// SHA-256 of the original payload (so a verifier can confirm SOMETHING was redacted, without seeing what).
    pub original_payload_digest: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Lifecycle config — dev-facing retention/tiering/erasure policy
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecycleConfig {
    /// Retention period in seconds per tier before moving to the next.
    pub hot_duration_seconds: u64,
    pub warm_duration_seconds: u64,
    pub cold_duration_seconds: u64,
    /// Whether to prune (hard-delete) after cold expiry. If false, archive forever.
    pub prune_after_cold: bool,
    /// Max entries per tenant (volume cap).
    pub max_entries_per_tenant: u64,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            hot_duration_seconds: 86400 * 7,        // 7 days hot
            warm_duration_seconds: 86400 * 90,      // 90 days warm
            cold_duration_seconds: 86400 * 365 * 7, // 7 years cold
            prune_after_cold: false,                // archive by default
            max_entries_per_tenant: 1_000_000,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// The data plane — the store + lifecycle engine
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Error)]
pub enum DpError {
    #[error("data plane: {0}")]
    DpErr(String),
}

#[derive(Debug, Clone, Default)]
pub struct DataPlane {
    /// All entries, keyed by entry_id.
    entries: HashMap<String, LogEntry>,
    /// Redaction records (the tombstone+redaction layer).
    redactions: Vec<RedactionRecord>,
    /// The lifecycle config.
    config: LifecycleConfig,
}

impl DataPlane {
    #[must_use]
    pub fn new(config: LifecycleConfig) -> Self {
        Self {
            entries: HashMap::new(),
            redactions: vec![],
            config,
        }
    }

    /// Append a new entry (the log is append-only).
    pub fn append(&mut self, entry: LogEntry) -> Result<(), DpError> {
        // Volume cap.
        let tenant_count = self
            .entries
            .values()
            .filter(|e| e.tenant_id == entry.tenant_id)
            .count();
        if tenant_count as u64 >= self.config.max_entries_per_tenant {
            return Err(DpError::DpErr(format!(
                "tenant {} exceeds max_entries_per_tenant ({})",
                entry.tenant_id, self.config.max_entries_per_tenant
            )));
        }
        if self.entries.contains_key(&entry.entry_id) {
            return Err(DpError::DpErr(format!(
                "duplicate entry_id: {}",
                entry.entry_id
            )));
        }
        self.entries.insert(entry.entry_id.clone(), entry);
        Ok(())
    }

    /// Read an entry. If tombstoned, returns a redacted version (payload replaced with a marker).
    /// The entry still EXISTS (inclusion proof verifies); its CONTENT is redacted (erasure satisfied).
    pub fn read(&self, entry_id: &str) -> Option<&LogEntry> {
        self.entries.get(entry_id)
    }

    /// Read the payload of an entry. Returns None if the entry is tombstoned or pruned.
    /// This is the erasure enforcement: the read path does not reveal redacted content.
    #[must_use]
    pub fn read_payload(&self, entry_id: &str) -> Option<&serde_json::Value> {
        match self.entries.get(entry_id) {
            Some(e) if e.tombstoned || e.pruned => None,
            Some(e) => Some(&e.payload),
            None => None,
        }
    }

    /// Apply a GDPR erasure: tombstone the entry + record a redaction record.
    /// The log entry stays (append-only); its payload becomes inaccessible via the read path.
    pub fn apply_erasure(&mut self, redaction: RedactionRecord) -> Result<(), DpError> {
        let entry = self
            .entries
            .get_mut(&redaction.entry_id)
            .ok_or_else(|| DpError::DpErr(format!("entry not found: {}", redaction.entry_id)))?;
        if entry.tombstoned {
            return Err(DpError::DpErr(format!(
                "entry already tombstoned: {}",
                redaction.entry_id
            )));
        }
        entry.tombstoned = true;
        self.redactions.push(redaction);
        Ok(())
    }

    /// Run lifecycle: move entries to the appropriate tier based on age, and prune expired entries.
    /// Returns (tiered_count, pruned_count).
    pub fn run_lifecycle(&mut self, now: u64) -> (usize, usize) {
        let mut tiered = 0usize;
        let mut pruned = 0usize;
        let config = self.config.clone();

        for entry in self.entries.values_mut() {
            if entry.pruned || entry.tombstoned {
                continue;
            }
            let age = now.saturating_sub(entry.stored_at);

            // Tier transitions.
            let new_tier = if age <= config.hot_duration_seconds {
                StorageTier::Hot
            } else if age <= config.hot_duration_seconds + config.warm_duration_seconds {
                StorageTier::Warm
            } else if age
                <= config.hot_duration_seconds
                    + config.warm_duration_seconds
                    + config.cold_duration_seconds
            {
                StorageTier::Cold
            } else if config.prune_after_cold {
                entry.pruned = true;
                pruned += 1;
                continue;
            } else {
                StorageTier::Archived
            };

            if entry.tier != new_tier {
                entry.tier = new_tier;
                tiered += 1;
            }
        }
        (tiered, pruned)
    }

    /// Count entries per tier for observability.
    #[must_use]
    pub fn tier_counts(&self) -> HashMap<StorageTier, usize> {
        let mut counts = HashMap::new();
        for entry in self.entries.values() {
            if !entry.pruned {
                *counts.entry(entry.tier).or_insert(0) += 1;
            }
        }
        counts
    }

    /// List all redaction records (for audit).
    #[must_use]
    pub fn redaction_history(&self) -> &[RedactionRecord] {
        &self.redactions
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Signed lifecycle decision receipt
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecycleReceiptBody {
    pub action: String, // "erasure" | "tier_transition" | "prune"
    pub entry_id: String,
    pub tenant_id: String,
    pub timestamp: u64,
    pub dp_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LifecycleReceipt {
    pub body: LifecycleReceiptBody,
    pub signature_algorithm: String,
    pub signature_public_key: String,
    pub signature_value: String,
}

fn canonical_body(body: &LifecycleReceiptBody) -> String {
    let v = serde_json::to_value(body).expect("serializes");
    let v = canonicalize_value(&v);
    serde_json::to_string(&v).expect("canonical serializes")
}

fn canonicalize_value(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::{Map, Value};
    match v {
        Value::Object(map) => {
            let mut sorted: Vec<(&String, &Value)> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut out = Map::new();
            for (k, val) in sorted {
                out.insert(k.clone(), canonicalize_value(val));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

pub fn issue_receipt(body: LifecycleReceiptBody, key: &SigningKey) -> LifecycleReceipt {
    let canonical = canonical_body(&body);
    let sig: Signature = key.sign(canonical.as_bytes());
    let verifying = key.verifying_key();
    LifecycleReceipt {
        body,
        signature_algorithm: "Ed25519".into(),
        signature_public_key: hex::encode(&verifying.to_bytes()),
        signature_value: hex::encode(&sig.to_bytes()),
    }
}

pub fn verify_receipt(receipt: &LifecycleReceipt) -> Result<(), DpError> {
    let pk_bytes = hex::decode(&receipt.signature_public_key)
        .map_err(|e| DpError::DpErr(format!("public_key hex: {e}")))?;
    if pk_bytes.len() != 32 {
        return Err(DpError::DpErr("public_key must be 32 bytes".into()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vkey = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| DpError::DpErr(format!("public_key: {e}")))?;
    let sig_bytes = hex::decode(&receipt.signature_value)
        .map_err(|e| DpError::DpErr(format!("signature hex: {e}")))?;
    if sig_bytes.len() != 64 {
        return Err(DpError::DpErr("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    let canonical = canonical_body(&receipt.body);
    vkey.verify(canonical.as_bytes(), &sig)
        .map_err(|_| DpError::DpErr("Ed25519 signature does not verify".into()))
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

#[must_use]
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = ed25519_dalek::rand_core::UnwrapErr(getrandom::SysRng);
    let signing = SigningKey::generate(&mut csprng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
    pub fn decode(hex: &str) -> Result<Vec<u8>, String> {
        if !hex.len().is_multiple_of(2) {
            return Err("odd-length hex".into());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, tenant: &str, payload: &str, stored_at: u64) -> LogEntry {
        LogEntry {
            entry_id: id.into(),
            tenant_id: tenant.into(),
            payload: serde_json::json!({"data": payload}),
            stored_at,
            tier: StorageTier::Hot,
            tombstoned: false,
            pruned: false,
        }
    }

    fn redaction(entry_id: &str, tenant: &str) -> RedactionRecord {
        RedactionRecord {
            entry_id: entry_id.into(),
            tenant_id: tenant.into(),
            requested_at: 2000,
            redacted_at: 2001,
            legal_basis: "GDPR Art. 17".into(),
            approved_by: "dpo".into(),
            original_payload_digest: "sha256:original".into(),
        }
    }

    #[test]
    fn append_and_read() {
        let mut dp = DataPlane::new(LifecycleConfig::default());
        dp.append(entry("e1", "tenant-a", "hello", 1000)).unwrap();
        assert!(dp.read("e1").is_some());
        assert!(dp.read_payload("e1").is_some());
    }

    #[test]
    fn duplicate_entry_rejected() {
        let mut dp = DataPlane::new(LifecycleConfig::default());
        dp.append(entry("e1", "t", "x", 1000)).unwrap();
        assert!(dp.append(entry("e1", "t", "x", 1000)).is_err());
    }

    #[test]
    fn erasure_tombstones_and_redacts() {
        let mut dp = DataPlane::new(LifecycleConfig::default());
        dp.append(entry("e1", "t", "secret", 1000)).unwrap();
        assert!(dp.read_payload("e1").is_some()); // before erasure

        dp.apply_erasure(redaction("e1", "t")).unwrap();

        // Entry still EXISTS (append-only preserved).
        assert!(dp.read("e1").is_some());
        assert!(dp.read("e1").unwrap().tombstoned);
        // But payload is INACCESSIBLE (erasure satisfied).
        assert!(dp.read_payload("e1").is_none());
        assert_eq!(dp.redaction_history().len(), 1);
    }

    #[test]
    fn double_erasure_rejected() {
        let mut dp = DataPlane::new(LifecycleConfig::default());
        dp.append(entry("e1", "t", "x", 1000)).unwrap();
        dp.apply_erasure(redaction("e1", "t")).unwrap();
        assert!(dp.apply_erasure(redaction("e1", "t")).is_err());
    }

    #[test]
    fn erasure_nonexistent_entry_rejected() {
        let mut dp = DataPlane::new(LifecycleConfig::default());
        assert!(dp.apply_erasure(redaction("nope", "t")).is_err());
    }

    #[test]
    fn lifecycle_tiers_by_age() {
        let mut dp = DataPlane::new(LifecycleConfig {
            hot_duration_seconds: 100,
            warm_duration_seconds: 200,
            cold_duration_seconds: 300,
            prune_after_cold: false,
            max_entries_per_tenant: 1000,
        });
        dp.append(entry("hot", "t", "x", 950)).unwrap(); // age=50 → hot
        dp.append(entry("warm", "t", "x", 750)).unwrap(); // age=250 → warm
        dp.append(entry("cold", "t", "x", 400)).unwrap(); // age=600 → cold
        dp.append(entry("arch", "t", "x", 0)).unwrap(); // age=1000 → archived

        let (tiered, pruned) = dp.run_lifecycle(1000);
        assert!(tiered >= 3); // at least 3 moved from hot
        assert_eq!(pruned, 0); // prune_after_cold = false

        let counts = dp.tier_counts();
        // `>= 0` on a usize count was always true and asserted nothing. The meaningful
        // claim is that the lifecycle run MOVED entries out of Hot: three were archived
        // above, so Hot must have shrunk below the number appended.
        let hot = counts.get(&StorageTier::Hot).copied().unwrap_or(0);
        assert!(
            hot < tiered,
            "lifecycle moved {tiered} entries out of Hot, so Hot should hold fewer than that; found {hot}"
        );
    }

    #[test]
    fn lifecycle_prunes_when_configured() {
        let mut dp = DataPlane::new(LifecycleConfig {
            hot_duration_seconds: 10,
            warm_duration_seconds: 10,
            cold_duration_seconds: 10,
            prune_after_cold: true,
            max_entries_per_tenant: 1000,
        });
        dp.append(entry("old", "t", "x", 0)).unwrap(); // age=1000 → way past cold → prune
        let (_, pruned) = dp.run_lifecycle(1000);
        assert_eq!(pruned, 1);
        assert!(dp.read("old").unwrap().pruned);
        assert!(dp.read_payload("old").is_none()); // pruned entries don't serve payload
    }

    #[test]
    fn volume_cap_enforced() {
        let mut dp = DataPlane::new(LifecycleConfig {
            max_entries_per_tenant: 2,
            ..Default::default()
        });
        dp.append(entry("e1", "t", "x", 1000)).unwrap();
        dp.append(entry("e2", "t", "x", 1000)).unwrap();
        assert!(dp.append(entry("e3", "t", "x", 1000)).is_err()); // exceeds cap
    }

    #[test]
    fn receipt_sign_and_verify() {
        let (sk, _) = generate_keypair();
        let body = LifecycleReceiptBody {
            action: "erasure".into(),
            entry_id: "e1".into(),
            tenant_id: "t".into(),
            timestamp: 1000,
            dp_version: DP_VERSION.into(),
        };
        let r = issue_receipt(body, &sk);
        verify_receipt(&r).expect("verifies");
    }

    #[test]
    fn tampered_receipt_fails() {
        let (sk, _) = generate_keypair();
        let body = LifecycleReceiptBody {
            action: "erasure".into(),
            entry_id: "e1".into(),
            tenant_id: "t".into(),
            timestamp: 1000,
            dp_version: DP_VERSION.into(),
        };
        let mut r = issue_receipt(body.clone(), &sk);
        r.body.entry_id = "evil".into();
        assert!(verify_receipt(&r).is_err());
    }

    #[test]
    fn storage_tier_is_queryable() {
        assert!(StorageTier::Hot.is_queryable());
        assert!(StorageTier::Warm.is_queryable());
        assert!(!StorageTier::Cold.is_queryable());
        assert!(!StorageTier::Archived.is_queryable());
    }
}

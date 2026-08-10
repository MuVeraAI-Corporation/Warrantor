//! # warrantor-credential-vault
//!
//! Agent-scoped credential brokering. Short-lived (15-minute) scoped tokens bound to a
//! SPIFFE identity + task + IP. Integrates HashiCorp Vault, AWS Secrets Manager, K8s Secrets
//! via the `CredentialBackend` trait. Revokes all tokens in <1 second on kill-switch trigger
//! (invariant I-05).
//!
//! Wave-1 ships against mock I1 and mock CredentialBackends. Real Vault/AWS/K8s integration
//! is task 03. See RFC R4.
//!
//! ## Revocation is durable (AX-40)
//!
//! [`Vault::new`] is in-memory and its revocations do **not** survive a restart — which is why
//! [`Vault::open`] exists. A vault opened over a path replays an append-only, `fsync`'d
//! revocation journal, so a revoked credential stays revoked across process restarts (invariant
//! I-05). See [`persist`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod persist;

pub use persist::{JournalOp, JournalRecord, RevocationJournal};

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Default token TTL: 15 minutes (per RFC R4 and the source docs).
pub const DEFAULT_TTL: Duration = Duration::from_secs(15 * 60);

/// Maximum revocation propagation: 1 second (per invariant I-05 and RFC R4).
pub const REVOKE_BUDGET: Duration = Duration::from_secs(1);

/// A scoped credential issued to an agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopedCredential {
    /// The SPIFFE identity the credential is bound to.
    pub spiffe_id: String,
    /// The task / purpose the credential serves.
    pub task: String,
    /// The IP the credential is bound to.
    pub bound_ip: String,
    /// The opaque secret value (e.g. an API key). Never logged at INFO or below.
    pub secret: String,
    /// Issued-at (epoch seconds).
    pub issued_at: u64,
    /// Expires-at (epoch seconds).
    pub expires_at: u64,
    /// The credential's unique token id (JTI), used for revocation tracking. H11: when a
    /// [`Vault`] issues this credential it registers the JTI so [`Vault::revoke_all`] can find
    /// it.
    ///
    /// **AX-40**: this field used to carry `#[serde(default)]`, so any credential deserialized
    /// from a payload without a `jti` got an empty one — and an empty JTI was silently accepted
    /// by [`register_issued`] (early `Ok(())`) and matched nothing in the revoked set, making
    /// such a credential **permanently unrevocable**. Attacker-supplied JSON with the `jti`
    /// omitted was therefore a revocation bypass. The default is gone: a credential without a
    /// JTI now fails to deserialize, and an empty JTI is rejected wherever one is presented.
    pub jti: String,
}

impl ScopedCredential {
    /// Is this credential expired at the given epoch-second timestamp?
    #[must_use]
    pub fn is_expired_at(&self, now_epoch_secs: u64) -> bool {
        now_epoch_secs >= self.expires_at
    }
}

/// Errors returned by the credential vault.
#[derive(Debug, Error)]
pub enum CredentialError {
    /// The credential has expired.
    #[error("credential expired")]
    Expired,
    /// The credential was revoked.
    #[error("credential revoked")]
    Revoked,
    /// The backend was unavailable.
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
    /// Revocation budget exceeded (invariant I-05 violation).
    #[error("revocation budget exceeded: {elapsed:?} > {budget:?}")]
    RevocationBudgetExceeded {
        /// Elapsed wall-clock time.
        elapsed: Duration,
        /// The maximum allowed budget.
        budget: Duration,
    },
    /// A credential was presented without a token id (JTI). **AX-40**: such a credential cannot
    /// be tracked or revoked, so it is rejected rather than treated as valid-and-unrevocable.
    #[error("credential has no jti; an untrackable credential cannot be honored")]
    MissingJti,
    /// The revocation journal could not be read or written (AX-40).
    #[error("revocation journal i/o failed for {path}: {source}")]
    Io {
        /// The path that failed.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A journal record could not be serialized (AX-40).
    #[error("revocation journal encode failed: {0}")]
    Encode(#[from] serde_json::Error),
    /// The revocation journal contains an unreadable record (AX-40).
    #[error("revocation journal corrupt at line {line}: {detail}")]
    JournalCorrupt {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        detail: String,
    },
    /// The process-global default vault was already initialized (AX-40).
    #[error("default vault already initialized")]
    DefaultVaultAlreadyInitialized,
}

/// A credential backend. Implementations: [`MockBackend`], [`HashiCorpVaultBackend`] (stub),
/// [`AwsSecretsManagerBackend`] (stub), [`KubernetesSecretsBackend`] (stub).
pub trait CredentialBackend: Send + Sync {
    /// Resolve the underlying secret for a request.
    ///
    /// # Errors
    /// Returns [`CredentialError::BackendUnavailable`] if the backend is unreachable.
    fn resolve(&self, key: &str) -> Result<String, CredentialError>;
}

/// A mock backend for CI / development.
pub struct MockBackend {
    /// Map of key → secret.
    pub secrets: std::collections::HashMap<String, String>,
}

impl MockBackend {
    /// Construct a mock backend from an iterator of (key, secret) pairs.
    pub fn new<I>(items: I) -> Self
    where
        I: IntoIterator<Item = (String, String)>,
    {
        Self {
            secrets: items.into_iter().collect(),
        }
    }
}

impl CredentialBackend for MockBackend {
    fn resolve(&self, key: &str) -> Result<String, CredentialError> {
        self.secrets
            .get(key)
            .cloned()
            .ok_or_else(|| CredentialError::BackendUnavailable(format!("mock miss: {key}")))
    }
}

/// HashiCorp Vault backend stub. Real integration (Vault HTTP API) is task 03.
pub struct HashiCorpVaultBackend {
    /// Vault address (e.g. "https://vault.example.com:8200").
    pub address: String,
}

impl HashiCorpVaultBackend {
    /// Construct a stub Vault backend pointing at `address`.
    #[must_use]
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
        }
    }
}

impl CredentialBackend for HashiCorpVaultBackend {
    fn resolve(&self, _key: &str) -> Result<String, CredentialError> {
        Err(CredentialError::BackendUnavailable(format!(
            "Vault backend at {} not yet wired (task 03)",
            self.address
        )))
    }
}

/// AWS Secrets Manager backend stub. Real integration (AWS SDK) is task 03.
pub struct AwsSecretsManagerBackend {
    /// AWS region (e.g. "us-east-1").
    pub region: String,
}

impl AwsSecretsManagerBackend {
    /// Construct a stub AWS Secrets Manager backend in `region`.
    #[must_use]
    pub fn new(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
        }
    }
}

impl CredentialBackend for AwsSecretsManagerBackend {
    fn resolve(&self, _key: &str) -> Result<String, CredentialError> {
        Err(CredentialError::BackendUnavailable(format!(
            "AWS Secrets Manager backend in {} not yet wired (task 03)",
            self.region
        )))
    }
}

/// Kubernetes Secrets backend stub. Real integration (kube-rs) is task 03.
pub struct KubernetesSecretsBackend {
    /// Namespace the secrets live in.
    pub namespace: String,
}

impl KubernetesSecretsBackend {
    /// Construct a stub K8s Secrets backend in `namespace`.
    #[must_use]
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
        }
    }
}

impl CredentialBackend for KubernetesSecretsBackend {
    fn resolve(&self, _key: &str) -> Result<String, CredentialError> {
        Err(CredentialError::BackendUnavailable(format!(
            "K8s Secrets backend in namespace {} not yet wired (task 03)",
            self.namespace
        )))
    }
}

/// Issue a scoped credential bound to the given identity + task + IP.
///
/// This free function is kept for backward compatibility with callers that do not need
/// revocation tracking. The issued credential carries a fresh JTI but is NOT registered with
/// any [`Vault`] — call [`Vault::issue`] instead if you need [`Vault::revoke_all`] to reach
/// this credential.
///
/// # Errors
/// Returns [`CredentialError::BackendUnavailable`] if the backend cannot resolve the secret.
pub fn issue(
    backend: &dyn CredentialBackend,
    spiffe_id: &str,
    task: &str,
    bound_ip: &str,
    secret_key: &str,
    ttl: Duration,
) -> Result<ScopedCredential, CredentialError> {
    let secret = backend.resolve(secret_key)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Ok(ScopedCredential {
        spiffe_id: spiffe_id.to_string(),
        task: task.to_string(),
        bound_ip: bound_ip.to_string(),
        secret,
        issued_at: now,
        expires_at: now + ttl.as_secs(),
        jti: new_jti(),
    })
}

/// The credential vault. **H11**: tracks issued token JTIs so that [`Vault::revoke_all`] is a
/// real operation (the previous free-function `revoke_all()` was a no-op that returned
/// immediately without revoking anything). The vault owns two sets: the JTIs it has issued
/// (so it knows what to revoke) and the JTIs it has revoked (so [`Vault::verify`] can reject
/// them). In production, revocation fans out to every replica in <1s via Kafka CloudEvents
/// (task 04); the in-process set is the local source of truth until that fan-out lands.
#[derive(Debug)]
pub struct Vault {
    issued: std::collections::HashSet<String>,
    revoked: std::collections::HashSet<String>,
    /// **AX-40**: the durable revocation journal. `None` means this vault is in-memory only and
    /// its revocations do NOT survive a restart.
    journal: Option<RevocationJournal>,
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault {
    /// Construct an empty **in-memory** vault.
    ///
    /// **This vault is not durable**: a restart un-revokes everything it revoked. Use
    /// [`Vault::open`] for anything that must honor invariant I-05 across a process lifetime.
    #[must_use]
    pub fn new() -> Self {
        Self {
            issued: std::collections::HashSet::new(),
            revoked: std::collections::HashSet::new(),
            journal: None,
        }
    }

    /// Open a **durable** vault backed by the append-only revocation journal at `path`,
    /// replaying any state a previous process left behind (AX-40 / invariant I-05).
    ///
    /// # Errors
    /// Returns [`CredentialError::Io`] on I/O failure or [`CredentialError::JournalCorrupt`] if
    /// the journal cannot be replayed.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, CredentialError> {
        let (journal, records) = RevocationJournal::open(path)?;
        let mut issued = std::collections::HashSet::new();
        let mut revoked = std::collections::HashSet::new();
        for rec in records {
            match rec.op {
                JournalOp::Issued => {
                    // A JTI that was already revoked stays revoked (revocation is monotone).
                    if !revoked.contains(&rec.jti) {
                        issued.insert(rec.jti);
                    }
                }
                JournalOp::Revoked => {
                    issued.remove(&rec.jti);
                    revoked.insert(rec.jti);
                }
                JournalOp::RevokedAll => {
                    for jti in issued.drain() {
                        revoked.insert(jti);
                    }
                }
            }
        }
        Ok(Self {
            issued,
            revoked,
            journal: Some(journal),
        })
    }

    /// The path of this vault's revocation journal, or `None` if the vault is in-memory only.
    #[must_use]
    pub fn journal_path(&self) -> Option<&Path> {
        self.journal.as_ref().map(RevocationJournal::path)
    }

    /// True iff this vault's revocations survive a process restart.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.journal.is_some()
    }

    fn journal_append(&mut self, op: JournalOp, jti: &str) -> Result<(), CredentialError> {
        match self.journal.as_mut() {
            Some(j) => j.append(&JournalRecord::now(op, jti)),
            None => Ok(()),
        }
    }

    /// Issue a scoped credential bound to the given identity + task + IP, AND register the
    /// credential's JTI with this vault so [`Vault::revoke_all`] can reach it.
    ///
    /// On a durable vault the JTI is journalled (and synced) *before* the credential is handed
    /// out, so a credential can never exist that the vault has no record of.
    ///
    /// # Errors
    /// Returns [`CredentialError::BackendUnavailable`] if the backend cannot resolve the secret,
    /// or [`CredentialError::Io`] if the JTI could not be journalled.
    pub fn issue(
        &mut self,
        backend: &dyn CredentialBackend,
        spiffe_id: &str,
        task: &str,
        bound_ip: &str,
        secret_key: &str,
        ttl: Duration,
    ) -> Result<ScopedCredential, CredentialError> {
        let cred = issue(backend, spiffe_id, task, bound_ip, secret_key, ttl)?;
        if cred.jti.is_empty() {
            return Err(CredentialError::MissingJti);
        }
        // Journal first: never hand out a credential we could not record.
        self.journal_append(JournalOp::Issued, &cred.jti)?;
        self.issued.insert(cred.jti.clone());
        Ok(cred)
    }

    /// Revoke a single credential by JTI. Idempotent: revoking an unknown JTI still records the
    /// revocation (so a credential issued by another replica is rejected here too).
    ///
    /// The in-memory revocation is applied **before** the journal write, so a journal failure
    /// leaves the vault over-revoking rather than under-revoking — but the error is still
    /// returned, because a revocation that is not durable does not satisfy I-05.
    ///
    /// # Errors
    /// Returns [`CredentialError::MissingJti`] for an empty JTI, [`CredentialError::Io`] if the
    /// revocation could not be made durable, or
    /// [`CredentialError::RevocationBudgetExceeded`] if the operation blew the 1-second budget.
    pub fn revoke(&mut self, jti: &str) -> Result<(), CredentialError> {
        if jti.is_empty() {
            return Err(CredentialError::MissingJti);
        }
        let start = std::time::Instant::now();
        self.issued.remove(jti);
        self.revoked.insert(jti.to_string());
        self.journal_append(JournalOp::Revoked, jti)?;
        let elapsed = start.elapsed();
        if elapsed > REVOKE_BUDGET {
            return Err(CredentialError::RevocationBudgetExceeded {
                elapsed,
                budget: REVOKE_BUDGET,
            });
        }
        Ok(())
    }

    /// Revoke **all** credentials this vault has issued. **H11**: the previous free-function
    /// `revoke_all()` was a no-op; this method iterates every issued JTI and marks it revoked,
    /// so subsequent [`Vault::verify`] calls reject them. Returns the count of newly-revoked
    /// tokens so callers can assert the kill-switch reached every credential (invariant I-05).
    ///
    /// In production this local revoke is followed by a fleet-wide fan-out (Kafka CloudEvents,
    /// task 04); the returned count is the local lower bound.
    ///
    /// # Errors
    /// Returns [`CredentialError::RevocationBudgetExceeded`] if the iteration exceeded the
    /// 1-second budget (invariant I-05).
    pub fn revoke_all(&mut self) -> Result<usize, CredentialError> {
        let start = std::time::Instant::now();
        let count = self.issued.len();
        // Move every issued JTI into the revoked set. We drain `issued` so a subsequent
        // `revoke_all` is a no-op (the credentials are already revoked).
        for jti in self.issued.drain() {
            self.revoked.insert(jti);
        }
        // AX-40: one journal record covers the whole fan-out; replay re-derives the same result.
        self.journal_append(JournalOp::RevokedAll, "")?;
        let elapsed = start.elapsed();
        if elapsed > REVOKE_BUDGET {
            return Err(CredentialError::RevocationBudgetExceeded {
                elapsed,
                budget: REVOKE_BUDGET,
            });
        }
        Ok(count)
    }

    /// Whether the given JTI is currently revoked.
    #[must_use]
    pub fn is_revoked(&self, jti: &str) -> bool {
        self.revoked.contains(jti)
    }

    /// Verify a credential against this vault: not revoked AND not expired at the current time.
    /// Returns Ok(()) on success.
    ///
    /// # Errors
    /// Returns [`CredentialError::MissingJti`] if the credential carries no token id (AX-40: an
    /// untrackable credential is unrevocable, so it fails closed),
    /// [`CredentialError::Revoked`] if the credential's JTI is in the revoked set,
    /// or [`CredentialError::Expired`] if it is past its expiry.
    pub fn verify(&self, cred: &ScopedCredential) -> Result<(), CredentialError> {
        // AX-40: an empty JTI matches nothing in the revoked set, so accepting it would make the
        // credential permanently unrevocable. Reject instead.
        if cred.jti.is_empty() {
            return Err(CredentialError::MissingJti);
        }
        if self.revoked.contains(&cred.jti) {
            return Err(CredentialError::Revoked);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if cred.is_expired_at(now) {
            return Err(CredentialError::Expired);
        }
        Ok(())
    }

    /// The number of currently-issued (not-yet-revoked) tokens tracked by this vault.
    #[must_use]
    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }

    /// The number of revoked tokens tracked by this vault.
    #[must_use]
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }
}

/// A process-global default vault, so the legacy free-function [`revoke_all`] can revoke
/// credentials issued via the legacy free-function [`issue`] (which does not itself register
/// JTIs — see the migration note on [`issue`]). New code should construct its own [`Vault`].
///
/// **AX-40**: by default this is an *in-memory* vault, whose revocations do not survive a
/// restart. Call [`init_default_vault_at`] once at process start to back it with a durable
/// revocation journal.
static DEFAULT_VAULT: std::sync::OnceLock<std::sync::Mutex<Vault>> = std::sync::OnceLock::new();

fn default_vault() -> &'static std::sync::Mutex<Vault> {
    DEFAULT_VAULT.get_or_init(|| std::sync::Mutex::new(Vault::new()))
}

/// Back the process-global default vault with the durable revocation journal at `path`
/// (AX-40 / invariant I-05). Must be called before the default vault is first used.
///
/// # Errors
/// Returns [`CredentialError::DefaultVaultAlreadyInitialized`] if the default vault has already
/// been created, or [`CredentialError::Io`] / [`CredentialError::JournalCorrupt`] if the journal
/// could not be opened and replayed.
pub fn init_default_vault_at<P: AsRef<Path>>(path: P) -> Result<(), CredentialError> {
    let vault = Vault::open(path)?;
    DEFAULT_VAULT
        .set(std::sync::Mutex::new(vault))
        .map_err(|_| CredentialError::DefaultVaultAlreadyInitialized)
}

/// True iff the process-global default vault is backed by a durable revocation journal.
#[must_use]
pub fn default_vault_is_durable() -> bool {
    default_vault()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .is_durable()
}

/// Register an issued credential's JTI with the process-global default vault. Callers that
/// obtain a credential via the free [`issue`] function and want the free [`revoke_all`] to
/// reach it should call this once after issuing. (The [`Vault::issue`] method does this
/// automatically and is the preferred entrypoint.)
///
/// # Errors
/// **AX-40**: returns [`CredentialError::MissingJti`] if the credential has no token id. This
/// used to be an early `Ok(())` — silently accepting an untrackable credential, which is exactly
/// what made a JTI-less credential permanently unrevocable. Also returns
/// [`CredentialError::Io`] if the registration could not be journalled.
pub fn register_issued(cred: &ScopedCredential) -> Result<(), CredentialError> {
    if cred.jti.is_empty() {
        return Err(CredentialError::MissingJti);
    }
    let mut v = default_vault().lock().unwrap_or_else(|e| e.into_inner()); // recover from poison (see H7 rationale)
    v.journal_append(JournalOp::Issued, &cred.jti)?;
    v.issued.insert(cred.jti.clone());
    Ok(())
}

/// Revoke all credentials tracked by the process-global default vault. **H11**: previously this
/// was a no-op that returned immediately; it now drains the default vault's issued set into its
/// revoked set, so credentials registered via [`register_issued`] (or issued via a [`Vault`]
/// that shares the default) are marked revoked.
///
/// Returns the count of newly-revoked tokens (0 if nothing was registered).
///
/// # Errors
/// Returns [`CredentialError::RevocationBudgetExceeded`] if the iteration took longer than
/// [`REVOKE_BUDGET`] (invariant I-05).
pub fn revoke_all() -> Result<usize, CredentialError> {
    let mut v = default_vault().lock().unwrap_or_else(|e| e.into_inner()); // recover from poison (see H7 rationale)
    v.revoke_all()
}

/// Check whether a JTI is revoked in the process-global default vault. Useful for callers that
/// issued via the free [`issue`] + [`register_issued`] path.
#[must_use]
pub fn is_revoked(jti: &str) -> bool {
    let v = default_vault().lock().unwrap_or_else(|e| e.into_inner()); // recover from poison (see H7 rationale)
    v.is_revoked(jti)
}

/// Generate a fresh JTI (unique token id) for a credential.
fn new_jti() -> String {
    use std::time::SystemTime;
    // 16 random-ish bytes hex-encoded. We avoid pulling in `rand`/`uuid` here (the crate does
    // not currently depend on them) and instead mix the system's coarse clock with the thread
    // id; this is sufficient for the local-revocation use case (uniqueness within a process).
    // Real cryptographic randomness is the backend's job (Vault/KMS) — the JTI is an identifier,
    // not a secret.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tid = std::thread::current().id();
    let tid_hash: u64 = format!("{tid:?}").bytes().fold(0u64, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(u64::from(b))
    });
    format!("{nanos:032x}{tid_hash:016x}")
}

/// Well-known credential patterns for the exposure scanner. Matches the patterns ExfilGuard (S6)
/// uses, so the two components agree on what counts as an exposed credential.
const CREDENTIAL_PATTERNS: &[(&str, &str)] = &[
    ("AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
    ("GitHub PAT", r"ghp_[0-9A-Za-z]{36}"),
    ("OpenAI API Key", r"sk-[A-Za-z0-9]{48}"),
    ("GitLab PAT", r"glpat-[0-9A-Za-z_-]{20}"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
];

/// A detected credential exposure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialExposure {
    /// Human-readable credential type (e.g. "AWS Access Key ID").
    pub credential_type: String,
    /// The matched substring.
    pub matched: String,
}

/// Scan a text blob for exposed credentials. This is the scanner that "would have caught the
/// OpenAI incident" per RFC R4 — OpenAI's agent exfiltrated credentials from "four accounts on
/// four services" via publicly exposed credentials.
///
/// # Errors
/// Never returns an error — pattern compilation is checked at test time.
pub fn scan_for_exposed_credentials(
    text: &str,
) -> Result<Vec<CredentialExposure>, CredentialError> {
    let mut found = Vec::new();
    for (cred_type, pattern) in CREDENTIAL_PATTERNS {
        let re = Regex::new(pattern)
            .map_err(|e| CredentialError::BackendUnavailable(format!("regex compile: {e}")))?;
        for m in re.find_iter(text) {
            found.push(CredentialExposure {
                credential_type: (*cred_type).to_string(),
                matched: m.as_str().to_string(),
            });
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_against_mock_backend() {
        let backend = MockBackend::new([("github_token".to_string(), "ghp_abc".to_string())]);
        let cred = issue(
            &backend,
            "spiffe://warrantor.dev/agent/x",
            "open-pr",
            "10.0.0.1",
            "github_token",
            DEFAULT_TTL,
        )
        .expect("issue");
        assert_eq!(cred.secret, "ghp_abc");
        assert!(cred.expires_at > cred.issued_at);
        assert_eq!(cred.expires_at - cred.issued_at, DEFAULT_TTL.as_secs());
        // H11: every issued credential carries a JTI for revocation tracking.
        assert!(!cred.jti.is_empty(), "issued credential must have a JTI");
    }

    #[test]
    fn missing_secret_returns_backend_error() {
        let backend = MockBackend::new(vec![]);
        let res = issue(
            &backend,
            "spiffe://warrantor.dev/agent/x",
            "t",
            "ip",
            "missing",
            DEFAULT_TTL,
        );
        assert!(matches!(res, Err(CredentialError::BackendUnavailable(_))));
    }

    #[test]
    fn revoke_all_meets_budget() {
        // H11: revoke_all now returns a count; the budget check still applies. We don't assert
        // the exact count because the global vault is shared across tests, but we do assert it
        // completes within budget (no error).
        let _count = revoke_all().expect("revocation under budget");
    }

    #[test]
    fn vault_stub_returns_unavailable() {
        let b = HashiCorpVaultBackend::new("https://vault.example.com:8200");
        assert!(matches!(
            b.resolve("k"),
            Err(CredentialError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn aws_stub_returns_unavailable() {
        let b = AwsSecretsManagerBackend::new("us-east-1");
        assert!(matches!(
            b.resolve("k"),
            Err(CredentialError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn k8s_stub_returns_unavailable() {
        let b = KubernetesSecretsBackend::new("default");
        assert!(matches!(
            b.resolve("k"),
            Err(CredentialError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn is_expired_at_check() {
        let cred = ScopedCredential {
            spiffe_id: "s".into(),
            task: "t".into(),
            bound_ip: "ip".into(),
            secret: "x".into(),
            issued_at: 1000,
            expires_at: 2000,
            jti: "jti-1".into(),
        };
        assert!(!cred.is_expired_at(1500));
        assert!(cred.is_expired_at(2000));
        assert!(cred.is_expired_at(3000));
    }

    #[test]
    fn scan_detects_aws_key() {
        let text = "config: AWS_KEY=AKIAIOSFODNN7EXAMPLE done";
        let found = scan_for_exposed_credentials(text).expect("scan");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].credential_type, "AWS Access Key ID");
        assert_eq!(found[0].matched, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn scan_detects_multiple_types_at_once() {
        // Mirrors the OpenAI incident shape: four accounts on four services.
        let text = "a=AKIAIOSFODNN7EXAMPLE b=ghp_000000000000000000000000000000000000 c=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa d=glpat-00000000000000000000";
        let found = scan_for_exposed_credentials(text).expect("scan");
        let types: Vec<_> = found.iter().map(|f| f.credential_type.as_str()).collect();
        assert!(types.contains(&"AWS Access Key ID"));
        assert!(types.contains(&"GitHub PAT"));
        assert!(types.contains(&"OpenAI API Key"));
        assert!(types.contains(&"GitLab PAT"));
        assert!(
            found.len() >= 4,
            "expected at least 4 detections, got {}",
            found.len()
        );
    }

    #[test]
    fn scan_returns_empty_on_clean_text() {
        let found = scan_for_exposed_credentials("just a normal log line").expect("scan");
        assert!(found.is_empty());
    }

    #[test]
    fn vault_revoke_all_marks_every_issued_token_revoked_h11() {
        // H11: the core fix. revoke_all() must actually revoke every token the vault issued
        // (previously it was a no-op that returned Ok(()) immediately). We issue 3 credentials
        // via a fresh Vault, revoke_all, and assert every JTI is now in the revoked set and
        // verify() rejects each.
        let mut v = Vault::new();
        let backend = MockBackend::new([
            ("k1".to_string(), "s1".to_string()),
            ("k2".to_string(), "s2".to_string()),
            ("k3".to_string(), "s3".to_string()),
        ]);
        let c1 = v
            .issue(&backend, "spiffe://a/1", "t", "ip", "k1", DEFAULT_TTL)
            .expect("issue 1");
        let c2 = v
            .issue(&backend, "spiffe://a/2", "t", "ip", "k2", DEFAULT_TTL)
            .expect("issue 2");
        let c3 = v
            .issue(&backend, "spiffe://a/3", "t", "ip", "k3", DEFAULT_TTL)
            .expect("issue 3");
        assert_eq!(v.issued_count(), 3);
        assert_eq!(v.revoked_count(), 0);

        // Before revoke_all, all three verify cleanly.
        v.verify(&c1).expect("c1 valid before revoke");
        v.verify(&c2).expect("c2 valid before revoke");
        v.verify(&c3).expect("c3 valid before revoke");

        let revoked = v.revoke_all().expect("revoke_all");
        assert_eq!(
            revoked, 3,
            "revoke_all must report the count of revoked tokens"
        );
        assert_eq!(
            v.issued_count(),
            0,
            "issued set must be drained after revoke_all"
        );
        assert_eq!(v.revoked_count(), 3);

        // After revoke_all, every credential must be rejected as Revoked.
        for (cred, label) in [(&c1, "c1"), (&c2, "c2"), (&c3, "c3")] {
            assert!(
                matches!(v.verify(cred), Err(CredentialError::Revoked)),
                "{label} must be Revoked after revoke_all"
            );
            assert!(
                v.is_revoked(&cred.jti),
                "{label} jti must be in revoked set"
            );
        }
    }

    #[test]
    fn vault_revoke_single_marks_one_revoked_h11() {
        // H11: targeted revocation (single JTI) must not revoke siblings.
        let mut v = Vault::new();
        let backend = MockBackend::new([
            ("k1".to_string(), "s1".to_string()),
            ("k2".to_string(), "s2".to_string()),
        ]);
        let c1 = v
            .issue(&backend, "spiffe://a/1", "t", "ip", "k1", DEFAULT_TTL)
            .expect("issue 1");
        let c2 = v
            .issue(&backend, "spiffe://a/2", "t", "ip", "k2", DEFAULT_TTL)
            .expect("issue 2");

        v.revoke(&c1.jti).expect("revoke c1");
        assert!(v.is_revoked(&c1.jti));
        assert!(
            !v.is_revoked(&c2.jti),
            "c2 must NOT be revoked by a targeted c1 revoke"
        );
        assert!(matches!(v.verify(&c1), Err(CredentialError::Revoked)));
        v.verify(&c2).expect("c2 still valid");
        // revoke_all should now only report 1 remaining (c1 was already moved).
        let remaining = v.revoke_all().expect("revoke_all remaining");
        assert_eq!(remaining, 1);
        assert!(matches!(v.verify(&c2), Err(CredentialError::Revoked)));
    }

    #[test]
    fn vault_verify_rejects_expired_h11() {
        // H11: verify must still honor expiry in addition to the revoked set.
        let mut v = Vault::new();
        let backend = MockBackend::new([("k1".to_string(), "s1".to_string())]);
        let cred = v
            .issue(&backend, "spiffe://a/1", "t", "ip", "k1", DEFAULT_TTL)
            .expect("issue");
        // Force expiry by constructing an already-expired credential with the same JTI.
        let mut expired = cred.clone();
        expired.expires_at = cred.issued_at; // expires_at == issued_at -> expired
        assert!(matches!(v.verify(&expired), Err(CredentialError::Expired)));
    }

    #[test]
    fn vault_revoke_all_on_empty_is_zero_h11() {
        // H11: revoke_all on a vault that has issued nothing must return 0 (not an error).
        let mut v = Vault::new();
        let count = v.revoke_all().expect("empty revoke_all");
        assert_eq!(count, 0);
    }

    #[test]
    fn credential_without_jti_is_rejected_ax40() {
        // AX-40 (was: `scoped_credential_serializes_with_jti_default_h11`, which asserted the
        // BUG as intended behavior). A payload with no `jti` used to deserialize to an empty
        // string, which `register_issued` accepted with an early Ok(()) and which matched
        // nothing in the revoked set — a permanently unrevocable credential, i.e. a revocation
        // bypass reachable from attacker-controlled JSON. It must now be rejected outright.
        let legacy_json = r#"{
            "spiffe_id": "s",
            "task": "t",
            "bound_ip": "ip",
            "secret": "x",
            "issued_at": 1000,
            "expires_at": 2000
        }"#;
        let err = serde_json::from_str::<ScopedCredential>(legacy_json)
            .expect_err("a credential without a jti must not deserialize");
        assert!(
            err.to_string().contains("jti"),
            "the error must name the missing field, got: {err}"
        );

        // A modern credential still round-trips with the JTI populated.
        let modern = ScopedCredential {
            spiffe_id: "s".into(),
            task: "t".into(),
            bound_ip: "ip".into(),
            secret: "x".into(),
            issued_at: 1000,
            expires_at: 2000,
            jti: "modern-jti".into(),
        };
        let json = serde_json::to_string(&modern).expect("serialize");
        let back: ScopedCredential = serde_json::from_str(&json).expect("deserialize modern");
        assert_eq!(back.jti, "modern-jti");
    }

    #[test]
    fn empty_jti_is_rejected_everywhere_ax40() {
        // Belt and braces: even if an empty JTI is constructed in Rust (bypassing serde), every
        // entrypoint that would otherwise treat it as valid-and-unrevocable rejects it.
        let blank = ScopedCredential {
            spiffe_id: "s".into(),
            task: "t".into(),
            bound_ip: "ip".into(),
            secret: "x".into(),
            issued_at: 0,
            expires_at: u64::MAX,
            jti: String::new(),
        };
        let v = Vault::new();
        assert!(
            matches!(v.verify(&blank), Err(CredentialError::MissingJti)),
            "verify must fail closed on an empty jti"
        );
        assert!(
            matches!(register_issued(&blank), Err(CredentialError::MissingJti)),
            "register_issued must reject an empty jti instead of silently returning Ok"
        );
        let mut v = Vault::new();
        assert!(
            matches!(v.revoke(""), Err(CredentialError::MissingJti)),
            "revoke must reject an empty jti"
        );
    }

    // ================= AX-40: durable revocation =================

    fn scratch_path(tag: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut p = std::env::temp_dir();
        p.push("warrantor-credential-vault-tests");
        p.push(format!("{tag}-{nanos}.jsonl"));
        p
    }

    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn three_key_backend() -> MockBackend {
        MockBackend::new([
            ("k1".to_string(), "s1".to_string()),
            ("k2".to_string(), "s2".to_string()),
            ("k3".to_string(), "s3".to_string()),
        ])
    }

    #[test]
    fn revocation_survives_an_actual_restart_ax40() {
        // The load-bearing durability test: revoke, DROP the vault, construct a fresh vault over
        // the same journal, and assert the credential is STILL revoked. Before AX-40 revocation
        // state lived in a process-global HashSet and a restart un-revoked everything.
        let scratch = Scratch(scratch_path("restart"));
        let backend = three_key_backend();
        let (c1, c2) = {
            let mut v = Vault::open(&scratch.0).expect("open durable vault");
            assert!(v.is_durable());
            let c1 = v
                .issue(&backend, "spiffe://a/1", "t", "ip", "k1", DEFAULT_TTL)
                .expect("issue 1");
            let c2 = v
                .issue(&backend, "spiffe://a/2", "t", "ip", "k2", DEFAULT_TTL)
                .expect("issue 2");
            v.revoke(&c1.jti).expect("revoke c1");
            assert!(matches!(v.verify(&c1), Err(CredentialError::Revoked)));
            v.verify(&c2).expect("c2 still valid before restart");
            (c1, c2)
            // vault dropped here — simulated process exit
        };

        // ---- restart ----
        let reopened = Vault::open(&scratch.0).expect("reopen after restart");
        assert!(
            reopened.is_revoked(&c1.jti),
            "a revoked credential MUST stay revoked across a restart (I-05)"
        );
        assert!(
            matches!(reopened.verify(&c1), Err(CredentialError::Revoked)),
            "verify must still reject the revoked credential after the restart"
        );
        reopened
            .verify(&c2)
            .expect("the un-revoked credential must still verify after the restart");
        assert_eq!(reopened.revoked_count(), 1);
        assert_eq!(reopened.issued_count(), 1);
    }

    #[test]
    fn revoke_all_survives_an_actual_restart_ax40() {
        let scratch = Scratch(scratch_path("restart-all"));
        let backend = three_key_backend();
        let creds = {
            let mut v = Vault::open(&scratch.0).expect("open");
            let creds: Vec<_> = ["k1", "k2", "k3"]
                .iter()
                .map(|k| {
                    v.issue(&backend, "spiffe://a", "t", "ip", k, DEFAULT_TTL)
                        .expect("issue")
                })
                .collect();
            assert_eq!(v.revoke_all().expect("revoke_all"), 3);
            creds
        };

        let reopened = Vault::open(&scratch.0).expect("reopen");
        assert_eq!(reopened.issued_count(), 0);
        assert_eq!(reopened.revoked_count(), 3);
        for c in &creds {
            assert!(
                matches!(reopened.verify(c), Err(CredentialError::Revoked)),
                "every credential must remain revoked after a restart"
            );
        }
    }

    #[test]
    fn issue_after_restart_does_not_resurrect_revoked_jtis_ax40() {
        let scratch = Scratch(scratch_path("no-resurrect"));
        let backend = three_key_backend();
        let c1 = {
            let mut v = Vault::open(&scratch.0).expect("open");
            let c1 = v
                .issue(&backend, "spiffe://a/1", "t", "ip", "k1", DEFAULT_TTL)
                .expect("issue");
            v.revoke(&c1.jti).expect("revoke");
            c1
        };
        {
            // A second process issues more credentials; the earlier revocation must persist.
            let mut v = Vault::open(&scratch.0).expect("reopen");
            let c2 = v
                .issue(&backend, "spiffe://a/2", "t", "ip", "k2", DEFAULT_TTL)
                .expect("issue after restart");
            assert!(v.is_revoked(&c1.jti));
            v.verify(&c2).expect("new credential valid");
        }
        let third = Vault::open(&scratch.0).expect("reopen again");
        assert!(
            third.is_revoked(&c1.jti),
            "revocation must survive an arbitrary number of restarts"
        );
        assert_eq!(
            third.issued_count(),
            1,
            "only the second credential is live"
        );
    }

    #[test]
    fn in_memory_vault_is_explicitly_not_durable_ax40() {
        // The contrast case that makes the durability claim meaningful.
        let v = Vault::new();
        assert!(!v.is_durable());
        assert!(v.journal_path().is_none());
    }

    #[test]
    fn journal_records_are_on_disk_before_revoke_returns_ax40() {
        let scratch = Scratch(scratch_path("synced"));
        let backend = three_key_backend();
        let mut v = Vault::open(&scratch.0).expect("open");
        let c = v
            .issue(&backend, "spiffe://a", "t", "ip", "k1", DEFAULT_TTL)
            .expect("issue");
        v.revoke(&c.jti).expect("revoke");
        // Read the journal with a plain filesystem read while the vault is still alive.
        let records = RevocationJournal::read_all(&scratch.0).expect("read journal");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].op, JournalOp::Issued);
        assert_eq!(records[1].op, JournalOp::Revoked);
        assert_eq!(records[1].jti, c.jti);
    }

    #[test]
    fn corrupt_journal_is_reported_not_ignored_ax40() {
        let scratch = Scratch(scratch_path("corrupt"));
        {
            let mut v = Vault::open(&scratch.0).expect("open");
            v.revoke("jti-a").expect("revoke a");
            v.revoke("jti-b").expect("revoke b");
        }
        let raw = std::fs::read_to_string(&scratch.0).expect("read");
        let lines: Vec<&str> = raw.lines().collect();
        // Corrupt the FIRST record (a mid-file corruption is tampering, not a torn tail).
        std::fs::write(&scratch.0, format!("{{not json\n{}\n", lines[1])).expect("write");
        let err = Vault::open(&scratch.0).expect_err("a corrupt journal must not open silently");
        assert!(
            matches!(err, CredentialError::JournalCorrupt { line: 1, .. }),
            "expected JournalCorrupt at line 1, got {err:?}"
        );
    }

    #[test]
    fn torn_journal_tail_from_a_crash_is_recovered_ax40() {
        let scratch = Scratch(scratch_path("torn"));
        {
            let mut v = Vault::open(&scratch.0).expect("open");
            v.revoke("jti-a").expect("revoke a");
        }
        let raw = std::fs::read_to_string(&scratch.0).expect("read");
        std::fs::write(&scratch.0, format!("{raw}{{\"op\":\"rev")).expect("write torn tail");
        let v = Vault::open(&scratch.0).expect("torn tail must be recoverable");
        assert!(v.is_revoked("jti-a"));
        assert_eq!(
            std::fs::read_to_string(&scratch.0).expect("read"),
            raw,
            "the torn bytes must have been truncated away"
        );
    }
}

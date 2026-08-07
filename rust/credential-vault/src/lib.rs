//! # aumos-credential-vault
//!
//! Agent-scoped credential brokering. Short-lived (15-minute) scoped tokens bound to a
//! SPIFFE identity + task + IP. Integrates HashiCorp Vault, AWS Secrets Manager, K8s Secrets
//! via the `CredentialBackend` trait. Revokes all tokens in <1 second on kill-switch trigger
//! (invariant I-05).
//!
//! Wave-1 ships against mock I1 and mock CredentialBackends. Real Vault/AWS/K8s integration
//! is task 03. See RFC R4.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use regex::Regex;
use serde::{Deserialize, Serialize};
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
    /// it. Defaults to an empty string for credentials deserialized from older snapshots.
    #[serde(default)]
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
pub struct Vault {
    issued: std::collections::HashSet<String>,
    revoked: std::collections::HashSet<String>,
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

impl Vault {
    /// Construct an empty vault.
    #[must_use]
    pub fn new() -> Self {
        Self {
            issued: std::collections::HashSet::new(),
            revoked: std::collections::HashSet::new(),
        }
    }

    /// Issue a scoped credential bound to the given identity + task + IP, AND register the
    /// credential's JTI with this vault so [`Vault::revoke_all`] can reach it.
    ///
    /// # Errors
    /// Returns [`CredentialError::BackendUnavailable`] if the backend cannot resolve the secret.
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
        self.issued.insert(cred.jti.clone());
        Ok(cred)
    }

    /// Revoke a single credential by JTI. Idempotent: revoking an unknown JTI is a no-op
    /// (returns Ok). Moves the JTI from `issued` to `revoked` if present.
    ///
    /// # Errors
    /// Returns [`CredentialError::RevocationBudgetExceeded`] only if the local set operations
    /// somehow exceeded the budget (vanishingly unlikely for an in-process HashSet).
    pub fn revoke(&mut self, jti: &str) -> Result<(), CredentialError> {
        let start = std::time::Instant::now();
        self.issued.remove(jti);
        self.revoked.insert(jti.to_string());
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
    /// Returns [`CredentialError::Revoked`] if the credential's JTI is in the revoked set,
    /// or [`CredentialError::Expired`] if it is past its expiry.
    pub fn verify(&self, cred: &ScopedCredential) -> Result<(), CredentialError> {
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
static DEFAULT_VAULT: std::sync::OnceLock<std::sync::Mutex<Vault>> = std::sync::OnceLock::new();

fn default_vault() -> &'static std::sync::Mutex<Vault> {
    DEFAULT_VAULT.get_or_init(|| std::sync::Mutex::new(Vault::new()))
}

/// Register an issued credential's JTI with the process-global default vault. Callers that
/// obtain a credential via the free [`issue`] function and want the free [`revoke_all`] to
/// reach it should call this once after issuing. (The [`Vault::issue`] method does this
/// automatically and is the preferred entrypoint.)
///
/// # Errors
/// Returns [`CredentialError::RevocationBudgetExceeded`] only if the budget was exceeded.
pub fn register_issued(cred: &ScopedCredential) -> Result<(), CredentialError> {
    if cred.jti.is_empty() {
        return Ok(()); // nothing to register (legacy credential with no JTI)
    }
    let mut v = default_vault()
        .lock()
        .unwrap_or_else(|e| e.into_inner()); // recover from poison (see H7 rationale)
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
    let mut v = default_vault()
        .lock()
        .unwrap_or_else(|e| e.into_inner()); // recover from poison (see H7 rationale)
    v.revoke_all()
}

/// Check whether a JTI is revoked in the process-global default vault. Useful for callers that
/// issued via the free [`issue`] + [`register_issued`] path.
#[must_use]
pub fn is_revoked(jti: &str) -> bool {
    let v = default_vault()
        .lock()
        .unwrap_or_else(|e| e.into_inner()); // recover from poison (see H7 rationale)
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
    let tid = std::thread::current()
        .id();
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
pub fn scan_for_exposed_credentials(text: &str) -> Result<Vec<CredentialExposure>, CredentialError> {
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
            "spiffe://aumos.dev/agent/x",
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
            "spiffe://aumos.dev/agent/x",
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
        assert!(found.len() >= 4, "expected at least 4 detections, got {}", found.len());
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
        assert_eq!(revoked, 3, "revoke_all must report the count of revoked tokens");
        assert_eq!(v.issued_count(), 0, "issued set must be drained after revoke_all");
        assert_eq!(v.revoked_count(), 3);

        // After revoke_all, every credential must be rejected as Revoked.
        for (cred, label) in [(&c1, "c1"), (&c2, "c2"), (&c3, "c3")] {
            assert!(
                matches!(v.verify(cred), Err(CredentialError::Revoked)),
                "{label} must be Revoked after revoke_all"
            );
            assert!(v.is_revoked(&cred.jti), "{label} jti must be in revoked set");
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
        assert!(!v.is_revoked(&c2.jti), "c2 must NOT be revoked by a targeted c1 revoke");
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
    fn scoped_credential_serializes_with_jti_default_h11() {
        // H11: legacy serialized credentials (no `jti` field) must still deserialize thanks to
        // #[serde(default)]. This protects callers that persisted ScopedCredential before H11.
        let legacy_json = r#"{
            "spiffe_id": "s",
            "task": "t",
            "bound_ip": "ip",
            "secret": "x",
            "issued_at": 1000,
            "expires_at": 2000
        }"#;
        let cred: ScopedCredential = serde_json::from_str(legacy_json).expect("deserialize legacy");
        assert_eq!(cred.jti, "", "legacy credential deserializes with empty jti");
        // And a modern credential round-trips with the JTI populated.
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
}

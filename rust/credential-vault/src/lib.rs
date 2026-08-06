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
    })
}

/// Revoke all credentials. In production this fans out to every replica in <1s.
/// Wave-1 mock: returns immediately; real fan-out via Kafka CloudEvents lands in task 04.
///
/// # Errors
/// Returns [`CredentialError::RevocationBudgetExceeded`] if the (mock) revocation took too long.
pub fn revoke_all() -> Result<(), CredentialError> {
    let start = std::time::Instant::now();
    // Mock: nothing to do. Real impl: publish `aumos.identity.revoked.v1` and wait for acks.
    let elapsed = start.elapsed();
    if elapsed > REVOKE_BUDGET {
        return Err(CredentialError::RevocationBudgetExceeded {
            elapsed,
            budget: REVOKE_BUDGET,
        });
    }
    Ok(())
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
        revoke_all().expect("revocation under budget");
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
}

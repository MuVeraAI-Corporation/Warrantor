//! # warrantor-secure-workspace (R1)
//!
//! A fail-closed orchestration boundary for signed workspace policy, approvals, credential
//! leases, isolated execution, and append-before-execute action evidence. Concrete sandbox,
//! credential, approval, and evidence services are dependency-injected so outages cannot be
//! replaced with local success.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use warrantor_trust_core::verification;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use thiserror::Error;

/// Workspace policy wire format.
pub const WORKSPACE_POLICY_FORMAT: &str = "osaf.secure-workspace/1";

/// Consequence classification used for approval enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SideEffectClass {
    /// No external mutation.
    Read,
    /// Non-consequential mutation.
    Write,
    /// Monetary side effect.
    Financial,
    /// Destructive side effect.
    Destructive,
    /// Physical-world side effect.
    Physical,
}

impl SideEffectClass {
    /// Whether explicit approval is mandatory.
    #[must_use]
    pub const fn is_consequential(self) -> bool {
        matches!(self, Self::Financial | Self::Destructive | Self::Physical)
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Financial => 2,
            Self::Destructive => 3,
            Self::Physical => 4,
        }
    }
}

/// Signed policy body. All strings are UTF-8 wire values, not host shell fragments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspacePolicy {
    /// Exact policy format.
    pub format: String,
    /// Stable policy ID.
    pub id: String,
    /// Monotonic policy revision.
    pub revision: u64,
    /// Exact agent SPIFFE ID authorized by this policy.
    pub agent_svid: String,
    /// Expiry in Unix epoch seconds.
    pub expires_at: u64,
    /// Executable names permitted inside the sandbox. Empty means no process spawning.
    pub allowed_commands: Vec<String>,
    /// Normalized absolute guest paths that may be accessed.
    pub filesystem_roots: Vec<String>,
    /// Exact `scheme://host[:port]` network origins permitted.
    pub network_allowlist: Vec<String>,
    /// Exact controlled inference origins permitted.
    pub inference_allowlist: Vec<String>,
    /// Credential references the broker may lease.
    pub credential_refs: Vec<String>,
    /// Highest consequence class that this policy permits.
    pub max_side_effect_class: SideEffectClass,
    /// Maximum command duration in milliseconds.
    pub max_duration_ms: u64,
    /// Maximum captured output bytes.
    pub max_output_bytes: u64,
}

impl WorkspacePolicy {
    fn validate(&self) -> Result<(), WorkspaceError> {
        if self.format != WORKSPACE_POLICY_FORMAT {
            return Err(WorkspaceError::InvalidPolicy(format!(
                "format must be {WORKSPACE_POLICY_FORMAT}"
            )));
        }
        if self.id.is_empty() || self.agent_svid.is_empty() {
            return Err(WorkspaceError::InvalidPolicy(
                "policy id and agent_svid are required".into(),
            ));
        }
        if !self.agent_svid.starts_with("spiffe://") {
            return Err(WorkspaceError::InvalidPolicy(
                "agent_svid must be a SPIFFE ID".into(),
            ));
        }
        if self.max_duration_ms == 0 || self.max_output_bytes == 0 {
            return Err(WorkspaceError::InvalidPolicy(
                "duration and output limits must be non-zero".into(),
            ));
        }
        validate_unique_values("allowed_commands", &self.allowed_commands)?;
        validate_unique_values("network_allowlist", &self.network_allowlist)?;
        validate_unique_values("inference_allowlist", &self.inference_allowlist)?;
        validate_unique_values("credential_refs", &self.credential_refs)?;
        validate_unique_values("filesystem_roots", &self.filesystem_roots)?;
        if self
            .filesystem_roots
            .iter()
            .any(|path| normalize_guest_path(path).as_deref() != Some(path.as_str()))
        {
            return Err(WorkspaceError::InvalidPolicy(
                "filesystem roots must be normalized absolute guest paths".into(),
            ));
        }
        if self
            .network_allowlist
            .iter()
            .chain(self.inference_allowlist.iter())
            .any(|origin| !is_normalized_origin(origin))
        {
            return Err(WorkspaceError::InvalidPolicy(
                "network and inference allowlists must contain normalized http(s) origins".into(),
            ));
        }
        Ok(())
    }

    /// Deterministic digest used in action evidence.
    ///
    /// # Errors
    /// Returns a policy error if validation or serialization fails.
    pub fn digest(&self) -> Result<String, WorkspaceError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| WorkspaceError::InvalidPolicy(error.to_string()))?;
        Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }
}

fn is_normalized_origin(origin: &str) -> bool {
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    if !matches!(scheme, "http" | "https")
        || authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.chars().any(char::is_whitespace)
    {
        return false;
    }
    if let Some(ipv6_and_port) = authority.strip_prefix('[') {
        let Some((address, port)) = ipv6_and_port.split_once(']') else {
            return false;
        };
        return !address.is_empty()
            && address.contains(':')
            && (port.is_empty() || valid_port_suffix(port));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-'))
        && port.is_none_or(|value| valid_port_suffix(&format!(":{value}")))
}

fn valid_port_suffix(port: &str) -> bool {
    let Some(port) = port.strip_prefix(':') else {
        return false;
    };
    port.parse::<u16>().is_ok_and(|value| value != 0)
}

fn validate_unique_values(field: &str, values: &[String]) -> Result<(), WorkspaceError> {
    let mut unique = BTreeSet::new();
    for value in values {
        if value.is_empty()
            || value.contains('\0')
            || value.contains('\r')
            || value.contains('\n')
            || !unique.insert(value)
        {
            return Err(WorkspaceError::InvalidPolicy(format!(
                "{field} contains an empty, duplicate, or unsafe value"
            )));
        }
    }
    Ok(())
}

fn normalize_guest_path(path: &str) -> Option<String> {
    if !path.starts_with('/') || path.contains('\0') || path.contains('\\') {
        return None;
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            value => components.push(value),
        }
    }
    Some(format!("/{}", components.join("/")))
}

fn path_is_within(path: &str, root: &str) -> bool {
    path == root
        || (root == "/")
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Policy plus T1 signature bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedWorkspacePolicy {
    /// Signed body.
    pub policy: WorkspacePolicy,
    /// Raw 64-byte Ed25519 signature over T1 canonical CBOR.
    pub signature: Vec<u8>,
}

/// Policy signature verification boundary.
pub trait PolicyVerifier: Send + Sync {
    /// Verify the policy signature.
    fn verify(&self, policy: &WorkspacePolicy, signature: &[u8]) -> Result<(), String>;
}

/// T1-backed Ed25519 policy verifier.
pub struct TrustCorePolicyVerifier {
    verifying_key: VerifyingKey,
}

impl TrustCorePolicyVerifier {
    /// Construct a verifier from the trusted issuer key.
    #[must_use]
    pub const fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }
}

impl PolicyVerifier for TrustCorePolicyVerifier {
    fn verify(&self, policy: &WorkspacePolicy, signature: &[u8]) -> Result<(), String> {
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| "policy signature must be 64 bytes".to_string())?;
        verification::verify(
            policy,
            &Signature::from_bytes(&signature_bytes),
            &self.verifying_key,
        )
        .map_err(|error| error.to_string())
    }
}

/// A requested isolated execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRequest {
    /// Authenticated agent SPIFFE ID.
    pub agent_svid: String,
    /// Executable name, passed without a shell.
    pub command: String,
    /// Individual process arguments.
    pub arguments: Vec<String>,
    /// Guest paths the execution intends to access.
    pub filesystem_paths: Vec<String>,
    /// Network origins the execution intends to access.
    pub network_origins: Vec<String>,
    /// Controlled inference origins the execution intends to use.
    pub inference_origins: Vec<String>,
    /// Credential references requested from the broker.
    pub credential_refs: Vec<String>,
    /// Consequence class.
    pub side_effect_class: SideEffectClass,
    /// Approval reference for consequential requests.
    pub approval_ref: Option<String>,
}

/// Opaque short-lived credential lease. Secret material never enters action evidence.
#[derive(Debug, Clone)]
pub struct CredentialLease {
    /// Broker-generated lease ID.
    pub id: String,
    /// Expiry in epoch seconds.
    pub expires_at: u64,
    /// Opaque environment bindings delivered only to the sandbox backend.
    pub environment: Vec<(String, String)>,
}

/// Credential broker boundary.
pub trait CredentialBroker: Send + Sync {
    /// Lease only the requested credential references for this agent.
    fn lease(
        &self,
        agent_svid: &str,
        credential_refs: &[String],
        expires_at: u64,
    ) -> Result<CredentialLease, String>;
    /// Revoke a lease during cleanup.
    fn revoke(&self, lease_id: &str) -> Result<(), String>;
}

/// Approval service boundary.
pub trait ApprovalGate: Send + Sync {
    /// Validate that an approval is current and bound to this exact request digest.
    fn validate(&self, approval_ref: &str, request_digest: &str) -> Result<(), String>;
}

/// Immutable evidence event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// Written before credential leasing, sandbox creation, or command execution.
    ExecutionIntent,
    /// Written after the backend returns or fails.
    ExecutionFinal,
}

/// Redacted action evidence. Arguments and credential values are deliberately absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEvent {
    /// Event type.
    pub kind: EvidenceKind,
    /// Policy digest.
    pub policy_digest: String,
    /// Request digest.
    pub request_digest: String,
    /// Agent identity.
    pub agent_svid: String,
    /// Outcome (`pending`, `succeeded`, or `failed`).
    pub outcome: String,
    /// Optional stable failure class.
    pub failure_class: Option<String>,
}

/// Append-only evidence boundary.
pub trait EvidenceSink: Send + Sync {
    /// Append and durably acknowledge one event, returning its sequence.
    fn append(&self, event: &EvidenceEvent) -> Result<u64, String>;
}

/// Backend execution configuration derived only from a verified policy.
#[derive(Debug, Clone)]
pub struct SandboxSpec {
    /// Network origins permitted by the verified policy.
    pub network_allowlist: Vec<String>,
    /// Guest filesystem roots permitted by the verified policy.
    pub filesystem_roots: Vec<String>,
    /// Maximum execution duration.
    pub max_duration_ms: u64,
    /// Maximum output bytes.
    pub max_output_bytes: u64,
}

/// Opaque sandbox handle.
#[derive(Debug, Clone)]
pub struct SandboxHandle {
    /// Backend-generated instance ID.
    pub id: String,
}

/// Backend result after bounded execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput {
    /// Process exit code.
    pub exit_code: i32,
    /// Captured standard output, already size-bounded by the backend.
    pub stdout: Vec<u8>,
    /// Captured standard error, already size-bounded by the backend.
    pub stderr: Vec<u8>,
}

/// Physical sandbox enforcement boundary (OpenShell/FORGE/R8 adapter).
pub trait SandboxBackend: Send + Sync {
    /// Create an isolated instance from verified policy limits.
    fn create(&self, spec: &SandboxSpec) -> Result<SandboxHandle, String>;
    /// Execute without a shell using a short-lived credential lease.
    fn execute(
        &self,
        handle: &SandboxHandle,
        request: &ExecutionRequest,
        lease: &CredentialLease,
    ) -> Result<ExecutionOutput, String>;
    /// Destroy the instance. Implementations must be idempotent.
    fn destroy(&self, handle: &SandboxHandle) -> Result<(), String>;
}

/// Successful workspace result with evidence correlations.
#[derive(Debug, Clone)]
pub struct WorkspaceResult {
    /// Backend execution output.
    pub output: ExecutionOutput,
    /// Sequence of the append-before-execute intent event.
    pub intent_sequence: u64,
    /// Sequence of the final event.
    pub final_sequence: u64,
}

/// Orchestrates the secure workspace transaction.
pub struct SecureWorkspace {
    policy_verifier: Box<dyn PolicyVerifier>,
    credential_broker: Box<dyn CredentialBroker>,
    approval_gate: Box<dyn ApprovalGate>,
    evidence_sink: Box<dyn EvidenceSink>,
    sandbox_backend: Box<dyn SandboxBackend>,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl SecureWorkspace {
    /// Construct the workspace from required enforcement dependencies.
    #[must_use]
    pub fn new(
        policy_verifier: Box<dyn PolicyVerifier>,
        credential_broker: Box<dyn CredentialBroker>,
        approval_gate: Box<dyn ApprovalGate>,
        evidence_sink: Box<dyn EvidenceSink>,
        sandbox_backend: Box<dyn SandboxBackend>,
        now: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            policy_verifier,
            credential_broker,
            approval_gate,
            evidence_sink,
            sandbox_backend,
            now,
        }
    }

    /// Validate policy and requested capabilities without touching external dependencies.
    ///
    /// # Errors
    /// Returns a typed validation or authorization failure.
    pub fn authorize(
        &self,
        signed_policy: &SignedWorkspacePolicy,
        request: &ExecutionRequest,
    ) -> Result<(String, String), WorkspaceError> {
        let policy = &signed_policy.policy;
        policy.validate()?;
        self.policy_verifier
            .verify(policy, &signed_policy.signature)
            .map_err(WorkspaceError::PolicySignatureInvalid)?;
        let now = (self.now)();
        if now >= policy.expires_at {
            return Err(WorkspaceError::PolicyExpired {
                expires_at: policy.expires_at,
                now,
            });
        }
        if request.agent_svid != policy.agent_svid {
            return Err(WorkspaceError::SubjectMismatch);
        }
        if request.side_effect_class.rank() > policy.max_side_effect_class.rank() {
            return Err(WorkspaceError::SideEffectDenied {
                requested: request.side_effect_class,
                maximum: policy.max_side_effect_class,
            });
        }
        if !policy.allowed_commands.contains(&request.command) {
            return Err(WorkspaceError::CommandDenied(request.command.clone()));
        }
        if request
            .arguments
            .iter()
            .any(|argument| argument.contains('\0'))
        {
            return Err(WorkspaceError::InvalidRequest(
                "arguments cannot contain NUL".into(),
            ));
        }
        for path in &request.filesystem_paths {
            let normalized = normalize_guest_path(path).ok_or_else(|| {
                WorkspaceError::FilesystemDenied(format!("invalid guest path: {path}"))
            })?;
            if normalized != *path
                || !policy
                    .filesystem_roots
                    .iter()
                    .any(|root| path_is_within(path, root))
            {
                return Err(WorkspaceError::FilesystemDenied(path.clone()));
            }
        }
        for origin in &request.network_origins {
            if !is_normalized_origin(origin) || !policy.network_allowlist.contains(origin) {
                return Err(WorkspaceError::NetworkDenied(origin.clone()));
            }
        }
        for origin in &request.inference_origins {
            if !is_normalized_origin(origin) || !policy.inference_allowlist.contains(origin) {
                return Err(WorkspaceError::InferenceDenied(origin.clone()));
            }
        }
        for credential_ref in &request.credential_refs {
            if !policy.credential_refs.contains(credential_ref) {
                return Err(WorkspaceError::CredentialDenied(credential_ref.clone()));
            }
        }
        let policy_digest = policy.digest()?;
        let request_bytes = serde_json::to_vec(request)
            .map_err(|error| WorkspaceError::InvalidRequest(error.to_string()))?;
        let request_digest = format!("sha256:{}", hex::encode(Sha256::digest(request_bytes)));
        if request.side_effect_class.is_consequential() {
            let approval_ref = request
                .approval_ref
                .as_deref()
                .ok_or(WorkspaceError::ApprovalRequired)?;
            self.approval_gate
                .validate(approval_ref, &request_digest)
                .map_err(WorkspaceError::ApprovalRejected)?;
        }
        Ok((policy_digest, request_digest))
    }

    /// Execute the fail-closed workspace transaction.
    ///
    /// # Errors
    /// No backend execution occurs unless authorization, approval, and durable intent evidence
    /// succeed. Credential and sandbox cleanup is attempted on every post-allocation path.
    pub fn execute(
        &self,
        signed_policy: &SignedWorkspacePolicy,
        request: &ExecutionRequest,
    ) -> Result<WorkspaceResult, WorkspaceError> {
        let (policy_digest, request_digest) = self.authorize(signed_policy, request)?;
        let intent_sequence = self
            .evidence_sink
            .append(&EvidenceEvent {
                kind: EvidenceKind::ExecutionIntent,
                policy_digest: policy_digest.clone(),
                request_digest: request_digest.clone(),
                agent_svid: request.agent_svid.clone(),
                outcome: "pending".into(),
                failure_class: None,
            })
            .map_err(WorkspaceError::IntentEvidenceUnavailable)?;

        let lease = self
            .credential_broker
            .lease(
                &request.agent_svid,
                &request.credential_refs,
                signed_policy.policy.expires_at,
            )
            .map_err(WorkspaceError::CredentialBrokerUnavailable)?;
        if let Err(message) =
            validate_credential_lease(&lease, (self.now)(), signed_policy.policy.expires_at)
        {
            let revoke_result = self.credential_broker.revoke(&lease.id);
            return Err(match revoke_result {
                Ok(()) => WorkspaceError::CredentialLeaseInvalid(message),
                Err(cleanup) => WorkspaceError::TransactionFailed(format!(
                    "invalid credential lease: {message}; credential cleanup failed: {cleanup}"
                )),
            });
        }
        let spec = SandboxSpec {
            network_allowlist: signed_policy.policy.network_allowlist.clone(),
            filesystem_roots: signed_policy.policy.filesystem_roots.clone(),
            max_duration_ms: signed_policy.policy.max_duration_ms,
            max_output_bytes: signed_policy.policy.max_output_bytes,
        };
        let handle = match self.sandbox_backend.create(&spec) {
            Ok(handle) => handle,
            Err(message) => {
                let _ = self.credential_broker.revoke(&lease.id);
                return Err(WorkspaceError::SandboxUnavailable(message));
            }
        };

        let raw_execution = self.sandbox_backend.execute(&handle, request, &lease);
        let (execution, output_limit) = match raw_execution {
            Ok(output) => match combined_output_bytes(&output) {
                Some(actual) if actual <= signed_policy.policy.max_output_bytes => {
                    (Ok(output), None)
                }
                actual => {
                    let actual = actual.unwrap_or(u64::MAX);
                    (
                        Err(format!(
                            "output limit exceeded: actual={actual}, maximum={}",
                            signed_policy.policy.max_output_bytes
                        )),
                        Some((actual, signed_policy.policy.max_output_bytes)),
                    )
                }
            },
            Err(message) => (Err(message), None),
        };
        let (outcome, failure_class) = match (&execution, output_limit) {
            (Ok(_), _) => ("succeeded", None),
            (Err(_), Some(_)) => ("failed", Some("output_limit_exceeded".to_string())),
            (Err(_), None) => ("failed", Some("sandbox_execution_failed".to_string())),
        };
        let final_event = self.evidence_sink.append(&EvidenceEvent {
            kind: EvidenceKind::ExecutionFinal,
            policy_digest,
            request_digest,
            agent_svid: request.agent_svid.clone(),
            outcome: outcome.into(),
            failure_class,
        });
        let destroy_result = self.sandbox_backend.destroy(&handle);
        let revoke_result = self.credential_broker.revoke(&lease.id);

        let mut failures = Vec::new();
        if let Err(message) = &execution {
            failures.push(format!("execution: {message}"));
        }
        if let Err(message) = &final_event {
            failures.push(format!("final evidence: {message}"));
        }
        if let Err(message) = &destroy_result {
            failures.push(format!("sandbox cleanup: {message}"));
        }
        if let Err(message) = &revoke_result {
            failures.push(format!("credential cleanup: {message}"));
        }
        if failures.len() > 1 {
            return Err(WorkspaceError::TransactionFailed(failures.join("; ")));
        }
        if let Some((actual, maximum)) = output_limit {
            return Err(WorkspaceError::OutputLimitExceeded { actual, maximum });
        }
        let output = execution.map_err(WorkspaceError::ExecutionFailed)?;
        let final_sequence = final_event.map_err(WorkspaceError::FinalEvidenceUnavailable)?;
        destroy_result.map_err(WorkspaceError::SandboxCleanupFailed)?;
        revoke_result.map_err(WorkspaceError::CredentialCleanupFailed)?;
        Ok(WorkspaceResult {
            output,
            intent_sequence,
            final_sequence,
        })
    }
}

fn combined_output_bytes(output: &ExecutionOutput) -> Option<u64> {
    output
        .stdout
        .len()
        .checked_add(output.stderr.len())
        .and_then(|length| u64::try_from(length).ok())
}

fn validate_credential_lease(
    lease: &CredentialLease,
    now: u64,
    policy_expires_at: u64,
) -> Result<(), String> {
    if lease.id.is_empty() || lease.id.contains(['\0', '\r', '\n']) {
        return Err("lease id is empty or unsafe".into());
    }
    if lease.expires_at <= now || lease.expires_at > policy_expires_at {
        return Err("lease expiry is outside the current policy lifetime".into());
    }
    let mut names = BTreeSet::new();
    for (name, value) in &lease.environment {
        if name.is_empty()
            || !name
                .chars()
                .all(|character| character == '_' || character.is_ascii_alphanumeric())
            || name.as_bytes()[0].is_ascii_digit()
            || value.contains('\0')
            || !names.insert(name)
        {
            return Err("lease environment contains an invalid or duplicate binding".into());
        }
    }
    Ok(())
}

/// Fail-closed workspace errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WorkspaceError {
    /// Policy structure is unsafe.
    #[error("invalid workspace policy: {0}")]
    InvalidPolicy(String),
    /// T1 rejected the policy signature.
    #[error("workspace policy signature invalid: {0}")]
    PolicySignatureInvalid(String),
    /// Policy expired.
    #[error("workspace policy expired at {expires_at}; now={now}")]
    PolicyExpired {
        /// Expiry.
        expires_at: u64,
        /// Trusted current time.
        now: u64,
    },
    /// Request agent and policy subject differ.
    #[error("request agent does not match policy subject")]
    SubjectMismatch,
    /// Requested consequence class exceeds the signed policy ceiling.
    #[error("side-effect class {requested:?} exceeds policy maximum {maximum:?}")]
    SideEffectDenied {
        /// Requested class.
        requested: SideEffectClass,
        /// Policy maximum.
        maximum: SideEffectClass,
    },
    /// Command is not allowlisted.
    #[error("command denied: {0}")]
    CommandDenied(String),
    /// Filesystem path is invalid or outside roots.
    #[error("filesystem path denied: {0}")]
    FilesystemDenied(String),
    /// Network origin is not allowlisted.
    #[error("network origin denied: {0}")]
    NetworkDenied(String),
    /// Inference origin is not allowlisted.
    #[error("inference origin denied: {0}")]
    InferenceDenied(String),
    /// Credential reference is not allowlisted.
    #[error("credential denied: {0}")]
    CredentialDenied(String),
    /// Request structure is invalid.
    #[error("invalid execution request: {0}")]
    InvalidRequest(String),
    /// Consequential action omitted approval.
    #[error("consequential execution requires approval")]
    ApprovalRequired,
    /// Approval service rejected or failed.
    #[error("approval rejected: {0}")]
    ApprovalRejected(String),
    /// Intent evidence was not durably accepted.
    #[error("intent evidence unavailable: {0}")]
    IntentEvidenceUnavailable(String),
    /// Credential lease failed.
    #[error("credential broker unavailable: {0}")]
    CredentialBrokerUnavailable(String),
    /// Credential broker returned a malformed or overlong lease.
    #[error("credential lease invalid: {0}")]
    CredentialLeaseInvalid(String),
    /// Sandbox creation failed.
    #[error("sandbox unavailable: {0}")]
    SandboxUnavailable(String),
    /// Sandbox execution failed.
    #[error("sandbox execution failed: {0}")]
    ExecutionFailed(String),
    /// Final evidence could not be persisted.
    #[error("final evidence unavailable: {0}")]
    FinalEvidenceUnavailable(String),
    /// Sandbox destruction failed.
    #[error("sandbox cleanup failed: {0}")]
    SandboxCleanupFailed(String),
    /// Credential revocation failed.
    #[error("credential cleanup failed: {0}")]
    CredentialCleanupFailed(String),
    /// Multiple post-allocation failures occurred and are reported together.
    #[error("workspace transaction failed: {0}")]
    TransactionFailed(String),
    /// Backend returned more output than the signed policy allowed.
    #[error("sandbox output exceeded limit: actual={actual}, maximum={maximum}")]
    OutputLimitExceeded {
        /// Actual combined stdout and stderr bytes.
        actual: u64,
        /// Signed policy maximum.
        maximum: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use warrantor_trust_core::signing::SigningKeyWrapper;
    use std::sync::Mutex;

    fn policy() -> WorkspacePolicy {
        WorkspacePolicy {
            format: WORKSPACE_POLICY_FORMAT.into(),
            id: "policy-1".into(),
            revision: 1,
            agent_svid: "spiffe://example.org/agent/coding-1".into(),
            expires_at: 2_000,
            allowed_commands: vec!["git".into()],
            filesystem_roots: vec!["/workspace".into()],
            network_allowlist: vec!["https://github.com".into()],
            inference_allowlist: vec!["https://inference.example.org".into()],
            credential_refs: vec!["vault://github/token".into()],
            max_side_effect_class: SideEffectClass::Destructive,
            max_duration_ms: 30_000,
            max_output_bytes: 1_000_000,
        }
    }

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            agent_svid: "spiffe://example.org/agent/coding-1".into(),
            command: "git".into(),
            arguments: vec!["status".into()],
            filesystem_paths: vec!["/workspace/repo".into()],
            network_origins: vec!["https://github.com".into()],
            inference_origins: vec![],
            credential_refs: vec!["vault://github/token".into()],
            side_effect_class: SideEffectClass::Read,
            approval_ref: None,
        }
    }

    struct AcceptVerifier;
    impl PolicyVerifier for AcceptVerifier {
        fn verify(&self, _policy: &WorkspacePolicy, _signature: &[u8]) -> Result<(), String> {
            Ok(())
        }
    }

    struct Broker {
        fail_lease: bool,
        fail_revoke: bool,
        lease_id: String,
        lease_expires_at: u64,
        revoked: Mutex<Vec<String>>,
    }
    impl CredentialBroker for Broker {
        fn lease(
            &self,
            _agent_svid: &str,
            _credential_refs: &[String],
            _expires_at: u64,
        ) -> Result<CredentialLease, String> {
            if self.fail_lease {
                return Err("vault unavailable".into());
            }
            Ok(CredentialLease {
                id: self.lease_id.clone(),
                expires_at: self.lease_expires_at,
                environment: vec![("TOKEN".into(), "secret".into())],
            })
        }

        fn revoke(&self, lease_id: &str) -> Result<(), String> {
            self.revoked
                .lock()
                .expect("revoke lock")
                .push(lease_id.into());
            if self.fail_revoke {
                Err("vault revoke failed".into())
            } else {
                Ok(())
            }
        }
    }

    struct Approval {
        reject: bool,
        calls: Mutex<usize>,
    }
    impl ApprovalGate for Approval {
        fn validate(&self, _approval_ref: &str, _request_digest: &str) -> Result<(), String> {
            *self.calls.lock().expect("approval lock") += 1;
            if self.reject {
                Err("approval invalid".into())
            } else {
                Ok(())
            }
        }
    }

    struct Evidence {
        fail_intent: bool,
        fail_final: bool,
        events: Mutex<Vec<EvidenceEvent>>,
    }
    impl EvidenceSink for Evidence {
        fn append(&self, event: &EvidenceEvent) -> Result<u64, String> {
            if (event.kind == EvidenceKind::ExecutionIntent && self.fail_intent)
                || (event.kind == EvidenceKind::ExecutionFinal && self.fail_final)
            {
                return Err("evidence unavailable".into());
            }
            let mut events = self.events.lock().expect("evidence lock");
            events.push(event.clone());
            Ok(events.len() as u64)
        }
    }

    struct Sandbox {
        fail_create: bool,
        fail_execute: bool,
        fail_destroy: bool,
        oversized_output: Option<usize>,
        calls: Mutex<Vec<&'static str>>,
    }
    impl SandboxBackend for Sandbox {
        fn create(&self, _spec: &SandboxSpec) -> Result<SandboxHandle, String> {
            self.calls.lock().expect("calls lock").push("create");
            if self.fail_create {
                Err("runtime unavailable".into())
            } else {
                Ok(SandboxHandle {
                    id: "sandbox-1".into(),
                })
            }
        }

        fn execute(
            &self,
            _handle: &SandboxHandle,
            _request: &ExecutionRequest,
            _lease: &CredentialLease,
        ) -> Result<ExecutionOutput, String> {
            self.calls.lock().expect("calls lock").push("execute");
            if self.fail_execute {
                Err("trapped".into())
            } else {
                Ok(ExecutionOutput {
                    exit_code: 0,
                    stdout: self
                        .oversized_output
                        .map_or_else(|| b"ok".to_vec(), |length| vec![b'x'; length]),
                    stderr: vec![],
                })
            }
        }

        fn destroy(&self, _handle: &SandboxHandle) -> Result<(), String> {
            self.calls.lock().expect("calls lock").push("destroy");
            if self.fail_destroy {
                Err("runtime cleanup failed".into())
            } else {
                Ok(())
            }
        }
    }

    fn workspace(
        broker: Broker,
        approval: Approval,
        evidence: Evidence,
        sandbox: Sandbox,
    ) -> SecureWorkspace {
        SecureWorkspace::new(
            Box::new(AcceptVerifier),
            Box::new(broker),
            Box::new(approval),
            Box::new(evidence),
            Box::new(sandbox),
            Box::new(|| 1_000),
        )
    }

    fn healthy_broker() -> Broker {
        Broker {
            fail_lease: false,
            fail_revoke: false,
            lease_id: "lease-1".into(),
            lease_expires_at: 1_500,
            revoked: Mutex::new(vec![]),
        }
    }

    fn healthy_approval() -> Approval {
        Approval {
            reject: false,
            calls: Mutex::new(0),
        }
    }

    fn healthy_evidence() -> Evidence {
        Evidence {
            fail_intent: false,
            fail_final: false,
            events: Mutex::new(vec![]),
        }
    }

    fn healthy_sandbox() -> Sandbox {
        Sandbox {
            fail_create: false,
            fail_execute: false,
            fail_destroy: false,
            oversized_output: None,
            calls: Mutex::new(vec![]),
        }
    }

    #[test]
    fn trust_core_verifier_accepts_t1_signature_and_rejects_tampering() {
        let signer = SigningKeyWrapper::generate();
        let policy = policy();
        let signature = signer.sign(&policy).expect("sign").to_bytes().to_vec();
        let verifier = TrustCorePolicyVerifier::new(signer.verifying_key());
        verifier
            .verify(&policy, &signature)
            .expect("valid signature");
        let mut tampered = policy;
        tampered.allowed_commands.push("sh".into());
        assert!(verifier.verify(&tampered, &signature).is_err());
    }

    #[test]
    fn execution_writes_intent_before_backend_and_cleans_up() {
        let result = workspace(
            healthy_broker(),
            healthy_approval(),
            healthy_evidence(),
            healthy_sandbox(),
        )
        .execute(
            &SignedWorkspacePolicy {
                policy: policy(),
                signature: vec![0; 64],
            },
            &request(),
        )
        .expect("workspace execution");
        assert_eq!(result.intent_sequence, 1);
        assert_eq!(result.final_sequence, 2);
        assert_eq!(result.output.stdout, b"ok");
    }

    #[test]
    fn authorization_rejects_capability_escape_attempts() {
        let workspace = workspace(
            healthy_broker(),
            healthy_approval(),
            healthy_evidence(),
            healthy_sandbox(),
        );
        let signed = SignedWorkspacePolicy {
            policy: policy(),
            signature: vec![0; 64],
        };
        let mut command = request();
        command.command = "sh".into();
        assert!(matches!(
            workspace.authorize(&signed, &command),
            Err(WorkspaceError::CommandDenied(_))
        ));
        let mut traversal = request();
        traversal.filesystem_paths = vec!["/workspace/../etc/passwd".into()];
        assert!(matches!(
            workspace.authorize(&signed, &traversal),
            Err(WorkspaceError::FilesystemDenied(_))
        ));
        let mut network = request();
        network.network_origins = vec!["https://evil.example".into()];
        assert!(matches!(
            workspace.authorize(&signed, &network),
            Err(WorkspaceError::NetworkDenied(_))
        ));
        let mut credential = request();
        credential.credential_refs = vec!["vault://root".into()];
        assert!(matches!(
            workspace.authorize(&signed, &credential),
            Err(WorkspaceError::CredentialDenied(_))
        ));
    }

    #[test]
    fn consequential_execution_requires_bound_approval() {
        let workspace = workspace(
            healthy_broker(),
            healthy_approval(),
            healthy_evidence(),
            healthy_sandbox(),
        );
        let signed = SignedWorkspacePolicy {
            policy: policy(),
            signature: vec![0; 64],
        };
        let mut consequential = request();
        consequential.side_effect_class = SideEffectClass::Destructive;
        assert_eq!(
            workspace.authorize(&signed, &consequential),
            Err(WorkspaceError::ApprovalRequired)
        );
        consequential.approval_ref = Some("approval-1".into());
        workspace
            .authorize(&signed, &consequential)
            .expect("approved request");
    }

    #[test]
    fn intent_outage_prevents_credential_or_sandbox_side_effects() {
        let sandbox = Sandbox {
            fail_create: false,
            fail_execute: false,
            fail_destroy: false,
            oversized_output: None,
            calls: Mutex::new(vec![]),
        };
        let result = workspace(
            healthy_broker(),
            healthy_approval(),
            Evidence {
                fail_intent: true,
                fail_final: false,
                events: Mutex::new(vec![]),
            },
            sandbox,
        )
        .execute(
            &SignedWorkspacePolicy {
                policy: policy(),
                signature: vec![0; 64],
            },
            &request(),
        );
        assert!(matches!(
            result,
            Err(WorkspaceError::IntentEvidenceUnavailable(_))
        ));
    }

    #[test]
    fn execution_failure_is_finalized_and_cleanup_is_attempted() {
        let result = workspace(
            healthy_broker(),
            healthy_approval(),
            healthy_evidence(),
            Sandbox {
                fail_create: false,
                fail_execute: true,
                fail_destroy: false,
                oversized_output: None,
                calls: Mutex::new(vec![]),
            },
        )
        .execute(
            &SignedWorkspacePolicy {
                policy: policy(),
                signature: vec![0; 64],
            },
            &request(),
        );
        assert!(matches!(result, Err(WorkspaceError::ExecutionFailed(_))));
    }

    #[test]
    fn signed_consequence_ceiling_and_origin_validation_fail_closed() {
        let workspace = workspace(
            healthy_broker(),
            healthy_approval(),
            healthy_evidence(),
            healthy_sandbox(),
        );
        let mut bounded_policy = policy();
        bounded_policy.max_side_effect_class = SideEffectClass::Write;
        let signed = SignedWorkspacePolicy {
            policy: bounded_policy,
            signature: vec![0; 64],
        };
        let mut financial = request();
        financial.side_effect_class = SideEffectClass::Financial;
        financial.approval_ref = Some("approval-1".into());
        assert!(matches!(
            workspace.authorize(&signed, &financial),
            Err(WorkspaceError::SideEffectDenied { .. })
        ));

        let mut unsafe_origin = policy();
        unsafe_origin.network_allowlist = vec!["https://github.com/path".into()];
        assert!(matches!(
            unsafe_origin.digest(),
            Err(WorkspaceError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn malformed_credential_lease_is_revoked_before_sandbox_creation() {
        let mut broker = healthy_broker();
        broker.lease_expires_at = 999;
        let result = workspace(
            broker,
            healthy_approval(),
            healthy_evidence(),
            healthy_sandbox(),
        )
        .execute(
            &SignedWorkspacePolicy {
                policy: policy(),
                signature: vec![0; 64],
            },
            &request(),
        );
        assert!(matches!(
            result,
            Err(WorkspaceError::CredentialLeaseInvalid(_))
        ));
    }

    #[test]
    fn backend_output_is_independently_bounded_and_reported_as_failure() {
        let mut bounded_policy = policy();
        bounded_policy.max_output_bytes = 1;
        let result = workspace(
            healthy_broker(),
            healthy_approval(),
            healthy_evidence(),
            healthy_sandbox(),
        )
        .execute(
            &SignedWorkspacePolicy {
                policy: bounded_policy,
                signature: vec![0; 64],
            },
            &request(),
        );
        assert_eq!(
            result.expect_err("two bytes must exceed one-byte limit"),
            WorkspaceError::OutputLimitExceeded {
                actual: 2,
                maximum: 1
            }
        );
    }

    #[test]
    fn simultaneous_execution_and_cleanup_failures_are_not_hidden() {
        let mut broker = healthy_broker();
        broker.fail_revoke = true;
        let result = workspace(
            broker,
            healthy_approval(),
            healthy_evidence(),
            Sandbox {
                fail_create: false,
                fail_execute: true,
                fail_destroy: true,
                oversized_output: None,
                calls: Mutex::new(vec![]),
            },
        )
        .execute(
            &SignedWorkspacePolicy {
                policy: policy(),
                signature: vec![0; 64],
            },
            &request(),
        );
        let WorkspaceError::TransactionFailed(message) =
            result.expect_err("all failures must be reported")
        else {
            panic!("expected aggregated transaction failure");
        };
        assert!(message.contains("execution: trapped"));
        assert!(message.contains("sandbox cleanup: runtime cleanup failed"));
        assert!(message.contains("credential cleanup: vault revoke failed"));
    }

    #[test]
    fn evidence_wire_shape_cannot_serialize_arguments_or_secrets() {
        let serialized = serde_json::to_string(&EvidenceEvent {
            kind: EvidenceKind::ExecutionIntent,
            policy_digest: "sha256:policy".into(),
            request_digest: "sha256:request".into(),
            agent_svid: "spiffe://example.org/agent/coding-1".into(),
            outcome: "pending".into(),
            failure_class: None,
        })
        .expect("serialize evidence");
        assert!(!serialized.contains("arguments"));
        assert!(!serialized.contains("credential"));
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn expired_and_subject_mismatched_policies_fail_before_dependencies() {
        let workspace = workspace(
            healthy_broker(),
            healthy_approval(),
            healthy_evidence(),
            healthy_sandbox(),
        );
        let mut expired = policy();
        expired.expires_at = 1_000;
        assert!(matches!(
            workspace.authorize(
                &SignedWorkspacePolicy {
                    policy: expired,
                    signature: vec![0; 64]
                },
                &request()
            ),
            Err(WorkspaceError::PolicyExpired { .. })
        ));
        let mut wrong_subject = request();
        wrong_subject.agent_svid = "spiffe://example.org/agent/other".into();
        assert_eq!(
            workspace.authorize(
                &SignedWorkspacePolicy {
                    policy: policy(),
                    signature: vec![0; 64]
                },
                &wrong_subject
            ),
            Err(WorkspaceError::SubjectMismatch)
        );
    }
}

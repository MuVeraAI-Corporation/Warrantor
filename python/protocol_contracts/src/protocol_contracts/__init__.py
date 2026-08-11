"""AumOS P1-P12 generated bindings and reference validation."""

from protocol_contracts.generated import (
    AgentActionReceipt,
    AgentAuthorityEnvelope,
    AgentIncidentExchange,
    AgentMemoryIntegrityRecord,
    AiArtifactTrustManifest,
    AutonomyBudgetSpecification,
    CapabilityAttestationProfile,
    ContextProvenanceEnvelope,
    MultiAgentDelegationExchange,
    ProofCarryingRemediationBundle,
    SecureSkillPackage,
    VerifiableEvaluationBundle,
)
from protocol_contracts.validation import (
    ErrorCode,
    ProtocolValidator,
    ValidationResult,
    canonical_signing_bytes,
)

__all__ = [
    "AgentActionReceipt",
    "AgentAuthorityEnvelope",
    "AgentIncidentExchange",
    "AgentMemoryIntegrityRecord",
    "AiArtifactTrustManifest",
    "AutonomyBudgetSpecification",
    "CapabilityAttestationProfile",
    "ContextProvenanceEnvelope",
    "ErrorCode",
    "MultiAgentDelegationExchange",
    "ProofCarryingRemediationBundle",
    "ProtocolValidator",
    "SecureSkillPackage",
    "ValidationResult",
    "VerifiableEvaluationBundle",
    "canonical_signing_bytes",
]

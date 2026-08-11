"""AumOS open-harness-spec (X3) — vendor-neutral agent harness specification.

Defines the five mandatory interfaces every AumOS-compatible agent harness must
implement. The interfaces are intentionally minimal: they describe ``what`` a
harness must expose, not ``how``. Every external integration (SPIRE, OPA, Kafka,
TPM, eval frameworks) is left to the harness implementer.

Interfaces (all :class:`typing.Protocol`):
    AgentIdentity        — who is running.
    ToolPermission       — may the agent call this tool, on this resource, with these args.
    AuditEvent           — what happened (structured).
    AttestationEnvelope  — was the harness trustworthy at the moment of the action.
    EvaluationReport     — did the agent meet the bar.

Plus :class:`ConformanceChecker`, which verifies a candidate harness object
implements all five interfaces and exposes the mandatory attributes/methods.

See ``docs/rfcs/X3-open-harness-spec.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

SPEC_VERSION = "1.0.0"
"""The open-harness-spec version this package implements."""


# ---------------------------------------------------------------------------
# Interface 1 — AgentIdentity
# ---------------------------------------------------------------------------
@runtime_checkable
class AgentIdentity(Protocol):
    """The identity surface of the agent running under the harness.

    A harness MUST expose the ``identity`` method returning an object with the
    four mandatory attributes below. Identity is propagated on every audit,
    policy decision, and attestation event.
    """

    @property
    def agent_id(self) -> str:
        """A stable, unique identifier for the agent instance."""
        ...

    @property
    def workload_id(self) -> str:
        """The workload/class identifier (e.g. model+revision)."""
        ...

    @property
    def spiffe_id(self) -> str:
        """The SPIFFE SVID URI bound to the agent (``""`` if none)."""
        ...

    @property
    def attributes(self) -> dict[str, str]:
        """Free-form attributes (clearance, scope, owner, ...)."""
        ...


# ---------------------------------------------------------------------------
# Interface 2 — ToolPermission
# ---------------------------------------------------------------------------
@runtime_checkable
class ToolPermission(Protocol):
    """The tool-call authorization surface.

    Every tool invocation MUST pass through ``authorize``. The return value is
    a :class:`PermissionDecision`.
    """

    def authorize(
        self,
        tool: str,
        resource: str,
        arguments: dict[str, Any] | None = None,
    ) -> PermissionDecision:
        """Decide whether the agent may invoke ``tool`` on ``resource``."""
        ...


@dataclass
class PermissionDecision:
    """The structured result of a tool-permission check."""

    allowed: bool
    reason: str = ""
    obligations: list[str] = field(default_factory=list)
    policy_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the decision to a plain dict."""
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "obligations": list(self.obligations),
            "policy_id": self.policy_id,
        }


# ---------------------------------------------------------------------------
# Interface 3 — AuditEvent
# ---------------------------------------------------------------------------
@runtime_checkable
class AuditEvent(Protocol):
    """The structured audit-event surface.

    A harness MUST emit a conforming event for every tool call, policy decision,
    and attestation gate. The event MUST carry the five mandatory fields below
    plus an ISO-8601 UTC timestamp.
    """

    @property
    def event_id(self) -> str:
        """A unique identifier for the event (UUID recommended)."""
        ...

    @property
    def agent_id(self) -> str:
        """The agent that produced the event."""
        ...

    @property
    def action(self) -> str:
        """The action performed (e.g. ``tool:invoke``, ``policy:check``)."""
        ...

    @property
    def resource(self) -> str:
        """The resource the action targeted."""
        ...

    @property
    def outcome(self) -> str:
        """``"allow"``, ``"deny"``, or ``"error"``."""
        ...

    @property
    def timestamp(self) -> str:
        """ISO-8601 UTC timestamp the event was emitted at."""
        ...


@dataclass
class DefaultAuditEvent:
    """A reference implementation of :class:`AuditEvent`.

    Concrete harnesses may use this directly or implement the protocol
    themselves.
    """

    agent_id: str
    action: str
    resource: str
    outcome: str
    event_id: str = ""
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id:
            import uuid

            self.event_id = str(uuid.uuid4())
        if not self.timestamp:
            self.timestamp = datetime.now(UTC).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Serialize the event to a plain dict."""
        return {
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "action": self.action,
            "resource": self.resource,
            "outcome": self.outcome,
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# Interface 4 — AttestationEnvelope
# ---------------------------------------------------------------------------
@runtime_checkable
class AttestationEnvelope(Protocol):
    """The hardware attestation surface.

    A harness MUST be able to produce a fresh attestation envelope for any
    nonce. The envelope carries a kind (``tpm``/``gpu``/``tee``), a
    measurement, the nonce, and a pass/fail flag.
    """

    def attest(self, nonce: str) -> AttestationReport:
        """Produce a fresh attestation tied to ``nonce``."""
        ...


@dataclass
class AttestationReport:
    """The structured attestation report returned by an AttestationEnvelope."""

    kind: str
    measurement: str
    nonce: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a plain dict."""
        return {
            "kind": self.kind,
            "measurement": self.measurement,
            "nonce": self.nonce,
            "passed": self.passed,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# Interface 5 — EvaluationReport
# ---------------------------------------------------------------------------
@runtime_checkable
class EvaluationReport(Protocol):
    """The evaluation surface.

    A harness MUST expose ``evaluate`` that runs a named evaluation against the
    agent and returns a conforming :class:`EvalResult`.
    """

    def evaluate(self, suite: str, config: dict[str, Any] | None = None) -> EvalResult:
        """Run the named ``suite`` evaluation against the agent."""
        ...


@dataclass
class EvalResult:
    """The structured evaluation result returned by an EvaluationReport."""

    suite: str
    passed: bool
    score: float
    metrics: dict[str, float] = field(default_factory=dict)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the result to a plain dict."""
        return {
            "suite": self.suite,
            "passed": self.passed,
            "score": self.score,
            "metrics": dict(self.metrics),
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# ConformanceChecker
# ---------------------------------------------------------------------------
@dataclass
class ConformanceResult:
    """The result of running :class:`ConformanceChecker` against a harness.

    ``checks`` is the ordered list of (interface_name, passed, reason) tuples.
    ``conforms`` is True iff every check passed.
    """

    checks: list[tuple[str, bool, str]] = field(default_factory=list)

    @property
    def conforms(self) -> bool:
        """True iff every interface check passed."""
        return all(p for _, p, _ in self.checks)

    @property
    def failures(self) -> list[str]:
        """The names of the interfaces that did not conform."""
        return [name for name, passed, _ in self.checks if not passed]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the conformance result to a plain dict."""
        return {
            "conforms": self.conforms,
            "spec_version": SPEC_VERSION,
            "checks": [{"interface": n, "passed": p, "reason": r} for n, p, r in self.checks],
        }


# Required attributes for each protocol, used when an object's Protocol class
# cannot be reliably isinstance-checked (e.g. when the harness is a duck type
# built without inheriting from the runtime_checkable Protocol).
_REQUIRED: dict[str, tuple[str, ...]] = {
    "AgentIdentity": ("agent_id", "workload_id", "spiffe_id", "attributes"),
    "ToolPermission": ("authorize",),
    "AuditEvent": (
        "event_id",
        "agent_id",
        "action",
        "resource",
        "outcome",
        "timestamp",
    ),
    "AttestationEnvelope": ("attest",),
    "EvaluationReport": ("evaluate",),
}

# Order matters: the checker reports in this order.
INTERFACE_NAMES = (
    "AgentIdentity",
    "ToolPermission",
    "AuditEvent",
    "AttestationEnvelope",
    "EvaluationReport",
)


class ConformanceChecker:
    """Verifies that a candidate harness implements all five mandatory interfaces.

    Usage::

        result = ConformanceChecker().check(my_harness)
        if not result.conforms:
            for name in result.failures:
                print(f"missing: {name}")

    The checker uses attribute-presence rather than ``isinstance`` because
    third-party harnesses are typically duck-typed and do not inherit from the
    runtime_checkable Protocols. Each missing method or attribute is reported
    as a distinct failure reason so the implementer can locate the gap.
    """

    def check(self, harness: Any) -> ConformanceResult:
        """Run all five interface checks against ``harness``."""
        result = ConformanceResult()
        for name in INTERFACE_NAMES:
            required = _REQUIRED[name]
            missing = [a for a in required if not hasattr(harness, a)]
            if missing:
                result.checks.append((name, False, f"missing: {', '.join(missing)}"))
            else:
                result.checks.append((name, True, "ok"))
        return result

    def check_many(self, harnesses: list[Any]) -> list[ConformanceResult]:
        """Run the checker against a list of harnesses and return each result."""
        return [self.check(h) for h in harnesses]


__all__ = [
    "INTERFACE_NAMES",
    "SPEC_VERSION",
    "AgentIdentity",
    "AttestationEnvelope",
    "AttestationReport",
    "AuditEvent",
    "ConformanceChecker",
    "ConformanceResult",
    "DefaultAuditEvent",
    "EvalResult",
    "EvaluationReport",
    "PermissionDecision",
    "ToolPermission",
]

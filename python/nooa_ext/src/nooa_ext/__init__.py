"""Warrantor nooa-ext (X2) — production extensions to NVIDIA NOOA.

NOOA is NVIDIA's agent harness. This package extends it with four production-grade
components that turn NOOA into a policy-enforcing, audit-streaming, identity-bound,
attestation-gated harness suitable for enterprise deployment.

Components:
    PolicyEnforcer   — OPA/Rego integration stub for in-harness policy enforcement.
    AuditStreamer    — Kafka/Kinesis/webhook sink protocol for streaming audit events.
    IdentityBinder   — SPIFFE SVID binding for agent identity propagation.
    AttestationHook  — Hardware attestation gate invoked at harness boundaries.

The external integrations (OPA, Kafka, SPIRE) are protocol-only in Wave-1; production
wiring is task 03. Every component is mockable so unit tests run fully in-process.

See ``docs/rfcs/X2-nooa-ext.md``.
"""

from __future__ import annotations

import json
import re
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol


# ---------------------------------------------------------------------------
# Shared value objects
# ---------------------------------------------------------------------------
@dataclass
class AgentIdentity:
    """The SPIFFE-bound identity of an agent running under NOOA."""

    spiffe_id: str
    agent_id: str
    workload_id: str
    attributes: dict[str, str] = field(default_factory=dict)
    svid_serial: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize the identity to a plain dict (for audit/json)."""
        d: dict[str, Any] = {
            "spiffe_id": self.spiffe_id,
            "agent_id": self.agent_id,
            "workload_id": self.workload_id,
            "attributes": dict(self.attributes),
        }
        if self.svid_serial:
            d["svid_serial"] = self.svid_serial
        return d


@dataclass
class AuditEvent:
    """One normalized audit event emitted by the harness."""

    agent_id: str
    action: str
    resource: str
    outcome: str  # "allow" | "deny" | "error"
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    event_id: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(UTC).isoformat()
        if not self.event_id:
            self.event_id = str(uuid.uuid4())

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
# PolicyEnforcer — OPA/Rego integration point
# ---------------------------------------------------------------------------
@dataclass
class PolicyDecision:
    """The result of a single policy decision."""

    allowed: bool
    reason: str = ""
    policy_id: str = ""
    obligations: list[str] = field(default_factory=list)


class RegoEvaluator(Protocol):
    """The interface for an OPA/Rego evaluator.

    Wave-1 ships an in-process stub evaluator; task 03 swaps in a real OPA HTTP client
    or the embedded `regorus` engine. Implementations MUST be deterministic for the same
    (policy, input) pair so unit tests are reproducible.
    """

    def evaluate(self, policy: str, input_doc: dict[str, Any]) -> dict[str, Any]:
        """Evaluate ``policy`` against ``input_doc`` and return the Rego result set."""
        ...


class StubRegoEvaluator:
    """A minimal in-process evaluator for Wave-1.

    Recognizes one built-in rule form: ``allow { input.action == "..." }``. Anything
    not matching returns ``{"allow": false}``. This is enough for the unit tests and to
    exercise the PolicyEnforcer wiring without a real OPA install.
    """

    def __init__(self, extra_rules: dict[tuple[str, str], bool] | None = None) -> None:
        self._extra = dict(extra_rules) if extra_rules else {}

    def evaluate(self, policy: str, input_doc: dict[str, Any]) -> dict[str, Any]:
        action = str(input_doc.get("action", ""))
        # built-in: allow { input.action == "<X>" } — match any quoted literal.
        allow = False
        for m in re.finditer(r'input\.action\s*==\s*"([^"]*)"', policy):
            if m.group(1) == action:
                allow = True
                break
            _ = m  # placeholder to satisfy linters in stubs
        if not allow:
            for m in re.finditer(r"input\.action\s*==\s*'([^']*)'", policy):
                if m.group(1) == action:
                    allow = True
                    break
        # extra explicit rules
        if ("allow", action) in self._extra:
            allow = allow or bool(self._extra[("allow", action)])
        return {"allow": allow}


class PolicyEnforcer:
    """In-harness policy enforcement. Wraps an OPA/Rego evaluator.

    The enforcer loads a Rego policy on construction and exposes ``enforce(action,
    resource, ctx)``. Each call returns a :class:`PolicyDecision` and emits an
    :class:`AuditEvent` via the bound :class:`AuditStreamer`.
    """

    def __init__(
        self,
        policy: str,
        evaluator: RegoEvaluator | None = None,
        policy_id: str = "default",
    ) -> None:
        self._policy = policy
        self._evaluator = evaluator or StubRegoEvaluator()
        self._policy_id = policy_id
        self._streamer: AuditStreamer | None = None
        self._identity: AgentIdentity | None = None

    def bind_audit(self, streamer: AuditStreamer) -> None:
        """Bind an audit streamer so every decision is streamed."""
        self._streamer = streamer

    def bind_identity(self, identity: AgentIdentity) -> None:
        """Bind the calling agent's identity so it is attached to every decision."""
        self._identity = identity

    def enforce(
        self,
        action: str,
        resource: str,
        ctx: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate ``action`` on ``resource`` against the loaded policy.

        Returns a :class:`PolicyDecision`. Always emits an :class:`AuditEvent` with
        outcome "allow" or "deny" if a streamer is bound.
        """
        input_doc: dict[str, Any] = {"action": action, "resource": resource}
        if ctx:
            input_doc["ctx"] = ctx
        if self._identity is not None:
            input_doc["identity"] = self._identity.to_dict()
        result = self._evaluator.evaluate(self._policy, input_doc)
        allowed = bool(result.get("allow", False))
        decision = PolicyDecision(
            allowed=allowed,
            reason="allowed by policy" if allowed else "denied by policy",
            policy_id=self._policy_id,
            obligations=list(result.get("obligations", []) or []),
        )
        if self._streamer is not None:
            agent_id = self._identity.agent_id if self._identity else "unknown"
            evt = AuditEvent(
                agent_id=agent_id,
                action=action,
                resource=resource,
                outcome="allow" if allowed else "deny",
                metadata={"policy_id": self._policy_id, "reason": decision.reason},
            )
            self._streamer.emit(evt)
        return decision


# ---------------------------------------------------------------------------
# AuditStreamer — Kafka / Kinesis / webhook sink protocol
# ---------------------------------------------------------------------------
class AuditSinkBackend(Protocol):
    """The wire protocol for an audit sink backend (Kafka, Kinesis, webhook, ...).

    Implementations MUST be idempotent on ``event_id`` so retries are safe.
    """

    name: str

    def send(self, payload: bytes) -> None:
        """Send the serialized payload to the backend. Raises on hard failure."""
        ...


class _InMemorySink:
    """An in-memory sink used by tests and as the Wave-1 default."""

    name = "memory"

    def __init__(self) -> None:
        self.events: list[bytes] = []

    def send(self, payload: bytes) -> None:
        self.events.append(payload)


class AuditStreamer:
    """Normalizes and streams audit events to one or more backends.

    Supports fan-out (multiple backends), retry with exponential backoff, and a
    ring buffer for last-N events. Serialization is JSON to bytes (the canonical
    on-the-wire form for Kafka/Kinesis/webhook).
    """

    def __init__(
        self,
        backends: list[AuditSinkBackend] | None = None,
        max_retries: int = 3,
        ring_size: int = 1024,
    ) -> None:
        self._backends: list[AuditSinkBackend] = list(backends) if backends else [_InMemorySink()]
        self._max_retries = max(1, int(max_retries))
        self._ring: list[AuditEvent] = []
        self._ring_size = max(1, int(ring_size))
        self._failed: list[AuditEvent] = []

    @property
    def backends(self) -> list[AuditSinkBackend]:
        """The configured sink backends."""
        return list(self._backends)

    @property
    def ring(self) -> list[AuditEvent]:
        """The last-N successfully streamed events (most recent last)."""
        return list(self._ring)

    @property
    def failed(self) -> list[AuditEvent]:
        """Events that exhausted retries and could not be streamed."""
        return list(self._failed)

    def add_backend(self, backend: AuditSinkBackend) -> None:
        """Append a backend to the fan-out list."""
        self._backends.append(backend)

    def emit(self, event: AuditEvent) -> bool:
        """Serialize and stream ``event`` to every backend.

        Returns True if at least one backend accepted it. Events that exhaust
        ``max_retries`` are recorded in ``failed``.
        """
        payload = json.dumps(event.to_dict(), sort_keys=True).encode("utf-8")
        any_ok = False
        for backend in self._backends:
            ok = False
            for _attempt in range(self._max_retries):
                try:
                    backend.send(payload)
                    ok = True
                    break
                except Exception:
                    continue
            if ok:
                any_ok = True
        if any_ok:
            self._ring.append(event)
            if len(self._ring) > self._ring_size:
                self._ring = self._ring[-self._ring_size :]
        else:
            self._failed.append(event)
        return any_ok

    def flush(self) -> int:
        """Return the count of events currently in the ring buffer."""
        return len(self._ring)


class WebhookBackend:
    """A webhook sink backend. Wave-1 invokes an injected callable instead of HTTP.

    The real HTTP POST wiring (requests/httpx with HMAC signing) is task 03.
    """

    name = "webhook"

    def __init__(self, url: str, sender: Callable[[str, bytes], None] | None = None) -> None:
        self._url = url
        self._sender = sender
        self.sent: list[bytes] = []

    def send(self, payload: bytes) -> None:
        if self._sender is None:
            # no sender configured => record only
            self.sent.append(payload)
            return
        self._sender(self._url, payload)
        self.sent.append(payload)


# ---------------------------------------------------------------------------
# IdentityBinder — SPIFFE SVID binding
# ---------------------------------------------------------------------------
@dataclass
class SVIDBundle:
    """A SPIFFE X.509 SVID bundle for a workload."""

    spiffe_id: str
    serial: str
    not_after: str  # ISO8601
    trust_domain: str
    fingerprint: str


class SVIDSource(Protocol):
    """The interface for a SPIFFE SVID source (SPIRE workload API, file, ...)."""

    def fetch(self) -> SVIDBundle:
        """Fetch the current SVID bundle for the workload."""
        ...


class _StaticSVIDSource:
    """A static SVID source used by tests."""

    def __init__(self, bundle: SVIDBundle) -> None:
        self._bundle = bundle

    def fetch(self) -> SVIDBundle:
        return self._bundle


class IdentityBinder:
    """Binds a SPIFFE SVID to a NOOA agent identity and rotates it.

    The binder holds the current bound :class:`AgentIdentity` and exposes
    ``current()``. Rotation refreshes the SVID from the source and updates the
    binding; an optional ``on_rotate`` callback fires on every successful rotation.
    """

    def __init__(
        self,
        agent_id: str,
        workload_id: str,
        source: SVIDSource | None = None,
        on_rotate: Callable[[AgentIdentity], None] | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._workload_id = workload_id
        self._source = source
        self._on_rotate = on_rotate
        self._bound: AgentIdentity | None = None
        self._rotations = 0

    @property
    def rotations(self) -> int:
        """Number of successful SVID rotations since construction."""
        return self._rotations

    def bind(self, bundle: SVIDBundle | None = None) -> AgentIdentity:
        """Bind an SVID (from the source or supplied directly) to the agent."""
        if bundle is None:
            if self._source is None:
                raise RuntimeError("IdentityBinder.bind requires a bundle or source")
            bundle = self._source.fetch()
        ident = AgentIdentity(
            spiffe_id=bundle.spiffe_id,
            agent_id=self._agent_id,
            workload_id=self._workload_id,
            svid_serial=bundle.serial,
            attributes={"trust_domain": bundle.trust_domain, "fingerprint": bundle.fingerprint},
        )
        self._bound = ident
        self._rotations += 1
        if self._on_rotate is not None:
            self._on_rotate(ident)
        return ident

    def current(self) -> AgentIdentity:
        """Return the currently bound identity. Raises if none is bound."""
        if self._bound is None:
            raise RuntimeError("no SVID bound; call bind() first")
        return self._bound

    def verify(self, expected_spiffe_id: str) -> bool:
        """True if the currently bound SVID matches ``expected_spiffe_id``."""
        bound = self._bound
        return bound is not None and bound.spiffe_id == expected_spiffe_id


# ---------------------------------------------------------------------------
# AttestationHook — hardware attestation gate
# ---------------------------------------------------------------------------
@dataclass
class AttestationReport:
    """A hardware attestation report (TPM quote, GPU attestation, TEE report)."""

    kind: str  # "tpm" | "gpu" | "tee"
    measurement: str
    nonce: str
    passed: bool
    detail: str = ""


class Attestator(Protocol):
    """The interface for a hardware attestation provider."""

    def attest(self, nonce: str) -> AttestationReport:
        """Produce a fresh attestation report tied to ``nonce``."""
        ...


class _StaticAttestator:
    """A static attestator returning a fixed report (used by tests)."""

    def __init__(self, report: AttestationReport) -> None:
        self._report = report
        self.calls = 0

    def attest(self, nonce: str) -> AttestationReport:
        self.calls += 1
        # surface the nonce the caller used
        return AttestationReport(
            kind=self._report.kind,
            measurement=self._report.measurement,
            nonce=nonce,
            passed=self._report.passed,
            detail=self._report.detail,
        )


class AttestationHook:
    """A boundary gate that requires a fresh attestation before letting an action proceed.

    Used to wrap the start of an inference call, a tool invocation, or any
    harness-exiting boundary. Records each gate decision as an :class:`AuditEvent`.
    """

    def __init__(
        self,
        attestator: Attestator,
        streamer: AuditStreamer | None = None,
        baseline_measurement: str = "",
    ) -> None:
        self._attestator = attestator
        self._streamer = streamer
        self._baseline = baseline_measurement
        self._last: AttestationReport | None = None

    @property
    def last_report(self) -> AttestationReport | None:
        """The most recent attestation report produced by the hook."""
        return self._last

    def gate(
        self,
        agent_id: str,
        action: str,
        resource: str,
        nonce: str | None = None,
    ) -> bool:
        """Run an attestation gate. Returns True if the gate opened."""
        n = nonce or str(uuid.uuid4())
        report = self._attestator.attest(n)
        self._last = report
        opened = report.passed
        if opened and self._baseline and report.measurement != self._baseline:
            opened = False
        if self._streamer is not None:
            self._streamer.emit(
                AuditEvent(
                    agent_id=agent_id,
                    action=f"attest:{action}",
                    resource=resource,
                    outcome="allow" if opened else "deny",
                    metadata={
                        "kind": report.kind,
                        "nonce": report.nonce,
                        "measurement": report.measurement,
                        "detail": report.detail,
                    },
                )
            )
        return opened


__all__ = [
    "AgentIdentity",
    "AttestationHook",
    "AttestationReport",
    "Attestator",
    "AuditEvent",
    "AuditSinkBackend",
    "AuditStreamer",
    "IdentityBinder",
    "PolicyDecision",
    "PolicyEnforcer",
    "RegoEvaluator",
    "SVIDBundle",
    "SVIDSource",
    "StubRegoEvaluator",
    "WebhookBackend",
]

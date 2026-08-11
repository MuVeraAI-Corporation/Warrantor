"""Tests for open-harness-spec: 5 interfaces + conformance checker."""

from __future__ import annotations

from typing import Any

from open_harness_spec import (
    SPEC_VERSION,
    AttestationReport,
    ConformanceChecker,
    DefaultAuditEvent,
    EvalResult,
    PermissionDecision,
)


# ---------------------------------------------------------------------------
# Reference harness — implements all five interfaces
# ---------------------------------------------------------------------------
class ReferenceHarness:
    """A harness that satisfies every interface."""

    def __init__(self) -> None:
        self._ident_attrs = {
            "agent_id": "agent-1",
            "workload_id": "w-1",
            "spiffe_id": "spiffe://muveraai.com/agent/1",
            "attributes": {"clearance": "3"},
        }

    # AgentIdentity
    @property
    def agent_id(self) -> str:
        return self._ident_attrs["agent_id"]

    @property
    def workload_id(self) -> str:
        return self._ident_attrs["workload_id"]

    @property
    def spiffe_id(self) -> str:
        return self._ident_attrs["spiffe_id"]

    @property
    def attributes(self) -> dict[str, str]:
        return self._ident_attrs["attributes"]

    # ToolPermission
    def authorize(
        self,
        tool: str,
        resource: str,
        arguments: dict[str, Any] | None = None,
    ) -> PermissionDecision:
        return PermissionDecision(allowed=True, reason="ok")

    # AuditEvent
    def last_event(self) -> DefaultAuditEvent:
        return DefaultAuditEvent(agent_id=self.agent_id, action="x", resource="r", outcome="allow")

    # These are present as attributes so the duck-type checker is happy.
    @property
    def event_id(self) -> str:
        return self.last_event().event_id

    @property
    def action(self) -> str:
        return self.last_event().action

    @property
    def resource(self) -> str:
        return self.last_event().resource

    @property
    def outcome(self) -> str:
        return self.last_event().outcome

    @property
    def timestamp(self) -> str:
        return self.last_event().timestamp

    # AttestationEnvelope
    def attest(self, nonce: str) -> AttestationReport:
        return AttestationReport(kind="tee", measurement="m", nonce=nonce, passed=True)

    # EvaluationReport
    def evaluate(self, suite: str, config: dict[str, Any] | None = None) -> EvalResult:
        return EvalResult(suite=suite, passed=True, score=1.0)


# ---------------------------------------------------------------------------
# ConformanceChecker
# ---------------------------------------------------------------------------
def test_conforms_when_all_five_interfaces_present() -> None:
    result = ConformanceChecker().check(ReferenceHarness())
    assert result.conforms
    assert result.failures == []


def test_reports_each_interface_check_in_order() -> None:
    result = ConformanceChecker().check(ReferenceHarness())
    names = [n for n, _, _ in result.checks]
    assert names == [
        "AgentIdentity",
        "ToolPermission",
        "AuditEvent",
        "AttestationEnvelope",
        "EvaluationReport",
    ]


def test_reports_missing_attributes_with_detail() -> None:
    class Empty:
        pass

    result = ConformanceChecker().check(Empty())
    assert not result.conforms
    assert len(result.failures) == 5
    # find the AgentIdentity failure and check the reason lists missing attrs
    ai = next(check for check in result.checks if check[0] == "AgentIdentity")
    assert not ai[1]
    assert "agent_id" in ai[2]


def test_partial_failure_reports_only_missing_interfaces() -> None:
    class Partial:
        def authorize(self, tool, resource, arguments=None):
            return PermissionDecision(allowed=True)

        def evaluate(self, suite, config=None):
            return EvalResult(suite=suite, passed=True, score=1.0)

    result = ConformanceChecker().check(Partial())
    assert not result.conforms
    assert "AgentIdentity" in result.failures
    assert "ToolPermission" not in result.failures
    assert "EvaluationReport" not in result.failures


def test_check_many_runs_each_harness() -> None:
    checker = ConformanceChecker()
    results = checker.check_many([ReferenceHarness(), type("E", (), {})()])
    assert results[0].conforms
    assert not results[1].conforms


def test_result_serializes_to_dict() -> None:
    result = ConformanceChecker().check(ReferenceHarness())
    d = result.to_dict()
    assert d["conforms"] is True
    assert d["spec_version"] == SPEC_VERSION
    assert len(d["checks"]) == 5


# ---------------------------------------------------------------------------
# Reference dataclasses
# ---------------------------------------------------------------------------
def test_default_audit_event_fills_id_and_timestamp() -> None:
    evt = DefaultAuditEvent(agent_id="a", action="x", resource="r", outcome="allow")
    assert evt.event_id
    assert evt.timestamp
    d = evt.to_dict()
    assert d["agent_id"] == "a"


def test_permission_decision_serializes() -> None:
    pd = PermissionDecision(allowed=False, reason="no", policy_id="p1")
    d = pd.to_dict()
    assert d["allowed"] is False
    assert d["policy_id"] == "p1"
    assert d["obligations"] == []


def test_attestation_report_serializes() -> None:
    r = AttestationReport(kind="gpu", measurement="m", nonce="n", passed=True)
    d = r.to_dict()
    assert d["passed"] is True
    assert d["kind"] == "gpu"


def test_eval_result_serializes_and_carries_metrics() -> None:
    r = EvalResult(suite="safety", passed=True, score=0.9, metrics={"toxicity": 0.01})
    d = r.to_dict()
    assert d["score"] == 0.9
    assert d["metrics"]["toxicity"] == 0.01

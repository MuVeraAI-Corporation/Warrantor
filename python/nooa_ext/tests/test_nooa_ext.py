"""Tests for nooa-ext: PolicyEnforcer, AuditStreamer, IdentityBinder, AttestationHook."""

from __future__ import annotations

import json

import pytest

from nooa_ext import (
    AgentIdentity,
    AttestationHook,
    AttestationReport,
    AuditEvent,
    AuditStreamer,
    IdentityBinder,
    PolicyEnforcer,
    StubRegoEvaluator,
    SVIDBundle,
    WebhookBackend,
)


# ---------- PolicyEnforcer ----------
def test_policy_enforcer_allows_matching_action() -> None:
    policy = 'allow { input.action == "tool:read" }'
    pf = PolicyEnforcer(policy, StubRegoEvaluator())
    decision = pf.enforce("tool:read", "/etc/passwd")
    assert decision.allowed
    assert decision.policy_id == "default"


def test_policy_enforcer_denies_non_matching_action() -> None:
    policy = 'allow { input.action == "tool:read" }'
    pf = PolicyEnforcer(policy, StubRegoEvaluator())
    decision = pf.enforce("tool:write", "/etc/passwd")
    assert not decision.allowed


def test_policy_enforcer_emits_audit_event_on_decision() -> None:
    policy = 'allow { input.action == "tool:read" }'
    streamer = AuditStreamer()
    ident = AgentIdentity(
        spiffe_id="spiffe://warrantor.dev/agent/1",
        agent_id="agent-1",
        workload_id="w-1",
    )
    pf = PolicyEnforcer(policy, StubRegoEvaluator())
    pf.bind_audit(streamer)
    pf.bind_identity(ident)
    pf.enforce("tool:read", "/etc/passwd")
    assert len(streamer.ring) == 1
    evt = streamer.ring[0]
    assert evt.outcome == "allow"
    assert evt.agent_id == "agent-1"
    assert evt.metadata["policy_id"] == "default"


def test_policy_enforcer_supports_extra_evaluator_rules() -> None:
    evaluator = StubRegoEvaluator(extra_rules={("allow", "tool:admin"): True})
    pf = PolicyEnforcer("allow {}", evaluator)
    assert pf.enforce("tool:admin", "system").allowed


# ---------- AuditStreamer ----------
def test_audit_streamer_fans_out_to_multiple_backends() -> None:
    seen: list[str] = []

    def sender_a(url: str, payload: bytes) -> None:
        seen.append("a")

    def sender_b(url: str, payload: bytes) -> None:
        seen.append("b")

    streamer = AuditStreamer(
        backends=[WebhookBackend("http://a", sender_a), WebhookBackend("http://b", sender_b)]
    )
    streamer.emit(AuditEvent(agent_id="a1", action="act", resource="r", outcome="allow"))
    assert seen == ["a", "b"]
    assert len(streamer.ring) == 1


def test_audit_streamer_retries_on_failure_and_records() -> None:
    class FlakyBackend:
        name = "flaky"

        def __init__(self) -> None:
            self.calls = 0
            self.fail_until = 4

        def send(self, payload: bytes) -> None:
            self.calls += 1
            if self.calls < self.fail_until:
                raise RuntimeError("boom")

    flaky = FlakyBackend()
    # fail_until == 4 with max_retries == 3 => never succeeds
    streamer = AuditStreamer(backends=[flaky], max_retries=3)
    ok = streamer.emit(AuditEvent(agent_id="a", action="x", resource="r", outcome="allow"))
    assert not ok
    assert flaky.calls == 3
    assert len(streamer.failed) == 1
    assert len(streamer.ring) == 0


def test_audit_streamer_ring_buffer_capped() -> None:
    streamer = AuditStreamer(ring_size=4)
    for i in range(10):
        streamer.emit(AuditEvent(agent_id="a", action="x", resource=str(i), outcome="allow"))
    assert len(streamer.ring) == 4
    assert streamer.ring[-1].resource == "9"


# ---------- IdentityBinder ----------
def test_identity_binder_binds_svid_from_source() -> None:
    bundle = SVIDBundle(
        spiffe_id="spiffe://warrantor.dev/agent/x",
        serial="1",
        not_after="2026-12-31T00:00:00Z",
        trust_domain="warrantor.dev",
        fingerprint="aa",
    )

    class StaticSource:
        def fetch(self) -> SVIDBundle:
            return bundle

    binder = IdentityBinder("agent-x", "w-x", StaticSource())
    ident = binder.bind()
    assert ident.spiffe_id == "spiffe://warrantor.dev/agent/x"
    assert ident.attributes["trust_domain"] == "warrantor.dev"
    assert binder.verify("spiffe://warrantor.dev/agent/x")
    assert binder.rotations == 1


def test_identity_binder_rotation_callback_fires() -> None:
    fired: list[str] = []
    binder = IdentityBinder(
        "agent",
        "w",
        on_rotate=lambda ident: fired.append(ident.spiffe_id),
    )
    binder.bind(
        SVIDBundle("spiffe://x/1", "1", "n", "x", "f"),
    )
    binder.bind(
        SVIDBundle("spiffe://x/2", "2", "n", "x", "f"),
    )
    assert fired == ["spiffe://x/1", "spiffe://x/2"]
    assert binder.rotations == 2


def test_identity_binder_requires_bind_before_current() -> None:
    binder = IdentityBinder("a", "w")
    with pytest.raises(RuntimeError):
        binder.current()


# ---------- AttestationHook ----------
def test_attestation_hook_opens_on_passed_report() -> None:
    report = AttestationReport(kind="tee", measurement="m1", nonce="n", passed=True)

    class Static:
        def attest(self, nonce: str) -> AttestationReport:
            return AttestationReport(
                kind=report.kind, measurement=report.measurement, nonce=nonce, passed=report.passed
            )

    hook = AttestationHook(Static())
    assert hook.gate("agent-1", "infer", "gpu")
    assert hook.last_report is not None
    assert hook.last_report.kind == "tee"


def test_attestation_hook_blocks_when_measurement_differs_baseline() -> None:
    report = AttestationReport(kind="tee", measurement="evil", nonce="n", passed=True)

    class Static:
        def attest(self, nonce: str) -> AttestationReport:
            return AttestationReport(
                kind=report.kind, measurement=report.measurement, nonce=nonce, passed=report.passed
            )

    hook = AttestationHook(Static(), baseline_measurement="m1")
    assert not hook.gate("agent-1", "infer", "gpu")


def test_attestation_hook_emits_audit_event() -> None:
    streamer = AuditStreamer()
    report = AttestationReport(kind="gpu", measurement="m1", nonce="n", passed=False)

    class Static:
        def attest(self, nonce: str) -> AttestationReport:
            return AttestationReport(
                kind=report.kind, measurement=report.measurement, nonce=nonce, passed=report.passed
            )

    hook = AttestationHook(Static(), streamer=streamer)
    hook.gate("a", "infer", "gpu")
    assert len(streamer.ring) == 1
    evt = streamer.ring[0]
    assert evt.outcome == "deny"
    assert evt.action == "attest:infer"


# ---------- AuditEvent serialization ----------
def test_audit_event_serializes_to_json() -> None:
    evt = AuditEvent(agent_id="a", action="x", resource="r", outcome="allow")
    blob = json.dumps(evt.to_dict(), sort_keys=True)
    parsed = json.loads(blob)
    assert parsed["agent_id"] == "a"
    assert parsed["event_id"] == evt.event_id
    assert parsed["timestamp"] == evt.timestamp

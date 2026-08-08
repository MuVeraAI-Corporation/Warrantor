"""Tests for aumos_vllm: lifecycle, attestation envelope, health, mock mode."""

from __future__ import annotations

import pytest

from aumos_vllm import (
    AttestationEnvelope,
    AttestedVLLMServer,
    HealthReport,
    HealthStatus,
)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
def test_start_mock_marks_started() -> None:
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/test")
    try:
        env = server.get_attestation_envelope()
        assert env.model_path == "/models/test"
    finally:
        server.stop()


def test_start_requires_model_path() -> None:
    server = AttestedVLLMServer(mode="mock")
    with pytest.raises(ValueError):
        server.start("")


def test_double_start_raises() -> None:
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/x")
    try:
        with pytest.raises(RuntimeError):
            server.start("/models/x")
    finally:
        server.stop()


def test_stop_is_safe_when_not_started() -> None:
    server = AttestedVLLMServer(mode="mock")
    server.stop()  # should not raise


def test_context_manager_stops_on_exit() -> None:
    with AttestedVLLMServer(mode="mock") as server:
        server.start("/models/ctx")
        assert server.health_check() is HealthStatus.HEALTHY
    # After exit, health reflects NOT_STARTED
    assert server.health_check() is HealthStatus.NOT_STARTED


# ---------------------------------------------------------------------------
# Attestation envelope
# ---------------------------------------------------------------------------
def test_envelope_is_mock_verified() -> None:
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/attest")
    try:
        env = server.get_attestation_envelope()
        assert isinstance(env, AttestationEnvelope)
        assert env.backend == "mock"
        assert env.digest.startswith("sha256:")
        assert env.verified is True
        # digest is derived from model + nonce
        assert env.report_data  # nonce populated
    finally:
        server.stop()


def test_envelope_serialises_to_dict() -> None:
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/ser")
    try:
        env = server.get_attestation_envelope()
        d = env.to_dict()
        assert d["model_path"] == "/models/ser"
        assert d["backend"] == "mock"
        assert "digest" in d
    finally:
        server.stop()


def test_get_envelope_before_start_raises() -> None:
    server = AttestedVLLMServer(mode="mock")
    with pytest.raises(RuntimeError):
        server.get_attestation_envelope()


# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------
def test_health_check_mock_no_attestation_required() -> None:
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/h", gpu_attestation_required=False)
    try:
        assert server.health_check() is HealthStatus.HEALTHY
    finally:
        server.stop()


def test_health_check_mock_with_attestation_required() -> None:
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/h2", gpu_attestation_required=True)
    try:
        # Mock envelope is verified, so HEALTHY
        assert server.health_check() is HealthStatus.HEALTHY
    finally:
        server.stop()


def test_health_check_before_start_is_not_started() -> None:
    server = AttestedVLLMServer(mode="mock")
    assert server.health_check() is HealthStatus.NOT_STARTED


def test_detailed_health_check_returns_report() -> None:
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/d")
    try:
        report = server.detailed_health_check()
        assert isinstance(report, HealthReport)
        assert report.status is HealthStatus.HEALTHY
        assert report.server_up is True
        assert report.attestation_ok is True
    finally:
        server.stop()


def test_attestation_failed_when_required_but_invalid() -> None:
    server = AttestedVLLMServer(mode="mock", attestation_backend="mock")
    server.start("/models/fail", gpu_attestation_required=True)
    try:
        # Tamper the envelope so verification would fail
        env = server.get_attestation_envelope()
        env.digest = "sha256:tampered"
        env.verified = False
        report = server.detailed_health_check()
        assert report.status is HealthStatus.ATTESTATION_FAILED
        assert report.server_up is True
        assert report.attestation_ok is False
    finally:
        server.stop()


# ---------------------------------------------------------------------------
# Mock inference
# ---------------------------------------------------------------------------
def test_mock_complete_returns_synthetic_response() -> None:
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/m")
    try:
        out = server.mock_complete("hello world")
        assert out["model"] == "/models/m"
        assert out["object"] == "chat.completion"
        assert "hello world" in out["choices"][0]["message"]["content"]
        assert "attested:" in out["choices"][0]["message"]["content"]
    finally:
        server.stop()


def test_mock_complete_requires_start() -> None:
    server = AttestedVLLMServer(mode="mock")
    with pytest.raises(RuntimeError):
        server.mock_complete("hi")


def test_envelope_digest_is_deterministic_per_instance() -> None:
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/same")
    try:
        env1 = server.get_attestation_envelope()
        # Calling again should return the same envelope (no re-collection)
        env2 = server.get_attestation_envelope()
        assert env1.digest == env2.digest
    finally:
        server.stop()

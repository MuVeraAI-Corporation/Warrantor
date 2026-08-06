"""Tests for cuda_gram MockBackend, AttestationVerifier, CCSession, and interop with the
Rust nvtrust-bridge JSON shape."""

from __future__ import annotations

import json

import pytest

from cuda_gram import (
    AttestationReport,
    AttestationVerifier,
    CCSession,
    MockBackend,
    establish_session,
)


def test_mock_backend_round_trips() -> None:
    backend = MockBackend()
    nonce = b"\x01" * 16
    report = backend.attest(nonce)
    assert report.nonce == nonce
    backend.verify(report)  # no raise


def test_mock_backend_rejects_tampered_report() -> None:
    backend = MockBackend()
    report = backend.attest(b"\x02" * 16)
    tampered = AttestationReport(
        gpu_model=report.gpu_model,
        attestation_bytes=b"tampered",
        nonce=report.nonce,
    )
    with pytest.raises(ValueError, match="attestation verification failed"):
        backend.verify(tampered)


def test_default_gpu_model() -> None:
    assert MockBackend().gpu_model == "mock-H100"


def test_attestation_verifier_returns_bool() -> None:
    backend = MockBackend()
    verifier = AttestationVerifier(backend)
    valid = backend.attest(b"\x03" * 16)
    tampered = AttestationReport(
        gpu_model="mock-H100",
        attestation_bytes=b"wrong",
        nonce=b"\x04" * 16,
    )
    assert verifier.verify(valid) is True
    assert verifier.verify(tampered) is False  # fail-closed, not raise


def test_establish_session_returns_verified_session() -> None:
    session = establish_session(MockBackend())
    assert isinstance(session, CCSession)
    assert session.verified is True
    assert session.gpu_model == "mock-H100"


def test_report_round_trips_through_dict() -> None:
    report = AttestationReport(
        gpu_model="mock-H100",
        attestation_bytes=b"abc",
        nonce=bytes(range(16)),
    )
    d = report.to_dict()
    assert d["gpu_model"] == "mock-H100"
    back = AttestationReport.from_dict(d)
    assert back == report


def test_from_dict_rejects_bad_nonce_length() -> None:
    with pytest.raises(ValueError, match="nonce must be 16 bytes"):
        AttestationReport.from_dict(
            {"gpu_model": "x", "attestation_bytes": [], "nonce": [0, 1, 2]}
        )


def test_interop_with_rust_cli_json_shape() -> None:
    """Lock the JSON shape produced by the Rust nvtrust-verify CLI.

    The Rust CLI emits:
      {"gpu_model": ..., "attestation_bytes": [...ints], "nonce": [...ints]}
    A Python caller must be able to parse it into an AttestationReport and verify it.
    """
    rust_json = json.dumps(
        {
            "gpu_model": "mock-H100",
            "attestation_bytes": list(b"aumos-mock-attestation"),
            "nonce": list(bytes(range(16))),
        }
    )
    report = AttestationReport.from_dict(json.loads(rust_json))
    backend = MockBackend()
    backend.verify(report)  # no raise — cross-language interop confirmed


def test_attest_rejects_wrong_nonce_length() -> None:
    with pytest.raises(ValueError, match="nonce must be 16 bytes"):
        MockBackend().attest(b"too short")

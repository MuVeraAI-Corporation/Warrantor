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
        AttestationReport.from_dict({"gpu_model": "x", "attestation_bytes": [], "nonce": [0, 1, 2]})


def test_interop_with_rust_cli_json_shape() -> None:
    """Lock the JSON shape produced by the Rust nvtrust-verify CLI.

    The Rust CLI emits:
      {"gpu_model": ..., "attestation_bytes": [...ints], "nonce": [...ints]}
    A Python caller must be able to parse it into an AttestationReport and verify it.
    """
    rust_json = json.dumps(
        {
            "gpu_model": "mock-H100",
            "attestation_bytes": list(b"warrantor-mock-attestation"),
            "nonce": list(bytes(range(16))),
        }
    )
    report = AttestationReport.from_dict(json.loads(rust_json))
    backend = MockBackend()
    backend.verify(report)  # no raise — cross-language interop confirmed


def test_attest_rejects_wrong_nonce_length() -> None:
    with pytest.raises(ValueError, match="nonce must be 16 bytes"):
        MockBackend().attest(b"too short")


def test_verify_with_challenge_accepts_matching_nonce_c4() -> None:
    # C4: a report verified against the same challenge nonce it was issued with must verify.
    backend = MockBackend()
    challenge = b"\x0a" * 16
    report = backend.attest(challenge)
    backend.verify_with_challenge(report, challenge)  # no raise


def test_verify_with_challenge_rejects_nonce_mismatch_c4() -> None:
    # C4: a report captured from a previous session (different nonce) must be rejected as a
    # replay even though its attestation_bytes are correct.
    backend = MockBackend()
    report = backend.attest(b"\x01" * 16)
    wrong_challenge = b"\x99" * 16
    with pytest.raises(ValueError, match="nonce mismatch"):
        backend.verify_with_challenge(report, wrong_challenge)


def test_verify_with_challenge_rejects_wrong_challenge_length_c4() -> None:
    backend = MockBackend()
    report = backend.attest(b"\x01" * 16)
    with pytest.raises(ValueError, match="challenge_nonce must be 16 bytes"):
        backend.verify_with_challenge(report, b"too short")


def test_verify_convenience_delegates_to_report_nonce_c4() -> None:
    # The backward-compatible verify() uses the report's own nonce — round-trips.
    backend = MockBackend()
    report = backend.attest(b"\x07" * 16)
    backend.verify(report)  # no raise


def test_interop_rust_json_report_rejects_mismatched_challenge_c4() -> None:
    # A report parsed from the Rust CLI JSON shape must also honor the challenge nonce.
    rust_json = json.dumps(
        {
            "gpu_model": "mock-H100",
            "attestation_bytes": list(b"warrantor-mock-attestation"),
            "nonce": list(bytes(range(16))),
        }
    )
    report = AttestationReport.from_dict(json.loads(rust_json))
    backend = MockBackend()
    backend.verify_with_challenge(report, bytes(range(16)))  # matches → ok
    with pytest.raises(ValueError, match="nonce mismatch"):
        backend.verify_with_challenge(report, b"\xff" * 16)

"""AumOS cuda-gram — high-level GPU attestation SDK.

Wave-1 v1.0 ships a pure-Python implementation that mirrors the proto types in
``proto/aumos/attestation/v1/report.proto``. The PyO3 binding to C1-1's Rust core
(``aumos-nvtrust-bridge``) lands in task 02 — it replaces the pure-Python
``MockBackend`` with a call into the Rust trusted core via PyO3, NOT ctypes (that's
the DefStack original we are migrating away from).

See ``docs/rfcs/C1-2-cuda-gram.md``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Protocol


class BoundaryCheck(IntEnum):
    """Mirrors ``aumos.attestation.v1.BoundaryCheck`` — the four pre-flight checks R2 runs."""

    UNSPECIFIED = 0
    NETWORK_ISOLATION = 1
    FILESYSTEM_BOUNDARY = 2
    PROCESS_ISOLATION = 3
    EGRESS_ATTESTATION = 4


class AttestationBackend(Protocol):
    """A backend that can issue and verify GPU attestation reports."""

    def attest(self, nonce: bytes) -> "AttestationReport":
        """Request an attestation report from the local GPU."""
        ...

    def verify(self, report: "AttestationReport") -> None:
        """Verify an attestation report. Raises if verification fails."""
        ...


@dataclass(frozen=True)
class AttestationReport:
    """A GPU attestation report. Mirrors the Rust ``AttestationReport`` in C1-1 and
    the proto type ``aumos.attestation.v1.GpuAttestationReport``."""

    gpu_model: str
    attestation_bytes: bytes
    nonce: bytes

    def to_dict(self) -> dict:
        """Serialize to a JSON-friendly dict matching the proto wire shape."""
        return {
            "gpu_model": self.gpu_model,
            "attestation_bytes": list(self.attestation_bytes),
            "nonce": list(self.nonce),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttestationReport":
        """Deserialize from a dict (the JSON shape produced by the Rust CLI)."""
        nonce = bytes(d["nonce"])
        if len(nonce) != 16:
            raise ValueError(f"nonce must be 16 bytes, got {len(nonce)}")
        return cls(
            gpu_model=d["gpu_model"],
            attestation_bytes=bytes(d["attestation_bytes"]),
            nonce=nonce,
        )


class AttestationVerifier:
    """Verifies attestation reports against a configured backend.

    The high-level entrypoint for any AumOS component that needs to confirm it's
    running in an attested confidential-compute environment (per RFC C1-2)."""

    def __init__(self, backend: AttestationBackend) -> None:
        self._backend = backend

    def verify(self, report: AttestationReport) -> bool:
        """Verify a report. Returns True on success, False on any failure.

        Fail-closed semantics (invariant I-09): a verify exception is converted to
        ``False`` rather than propagated, so callers cannot accidentally proceed
        on an attestation failure."""
        try:
            self._backend.verify(report)
            return True
        except Exception:  # noqa: BLE001 — fail-closed
            return False


@dataclass
class CCSession:
    """A confidential-compute session, established after a successful attestation.

    Per RFC C1-2: the session holds the verified report and is the scope within
    which downstream components (C1-3 attesta-flow, C1-4 tee-serve) operate."""

    report: AttestationReport
    verified: bool

    @property
    def gpu_model(self) -> str:
        """The GPU model backing this session."""
        return self.report.gpu_model


class MockBackend:
    """A mock backend for CI / offline / development use.

    Always issues reports with the well-known mock attestation bytes; verifies
    any report whose attestation bytes match the mock marker. Mirrors the Rust
    ``MockBackend`` in ``aumos-nvtrust-bridge`` byte-for-byte so a report issued
    by the Rust CLI verifies here and vice versa."""

    MOCK_ATTESTATION_BYTES = b"aumos-mock-attestation"

    def __init__(self, gpu_model: str = "mock-H100") -> None:
        self.gpu_model = gpu_model

    def attest(self, nonce: bytes) -> AttestationReport:
        if len(nonce) != 16:
            raise ValueError(f"nonce must be 16 bytes, got {len(nonce)}")
        return AttestationReport(
            gpu_model=self.gpu_model,
            attestation_bytes=self.MOCK_ATTESTATION_BYTES,
            nonce=nonce,
        )

    def verify(self, report: AttestationReport) -> None:
        if report.attestation_bytes != self.MOCK_ATTESTATION_BYTES:
            raise ValueError("attestation verification failed")


def establish_session(backend: AttestationBackend, nonce: bytes | None = None) -> CCSession:
    """High-level convenience: attest against ``backend`` and return a verified CCSession.

    If ``nonce`` is None, a 16-byte zero nonce is used (CI/dev only; real callers
    should pass an OsRng nonce)."""
    if nonce is None:
        nonce = bytes(16)
    report = backend.attest(nonce)
    verifier = AttestationVerifier(backend)
    verified = verifier.verify(report)
    return CCSession(report=report, verified=verified)


__all__ = [
    "AttestationBackend",
    "AttestationReport",
    "AttestationVerifier",
    "BoundaryCheck",
    "CCSession",
    "MockBackend",
    "establish_session",
]

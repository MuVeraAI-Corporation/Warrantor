"""AumOS vLLM Integration — attested LLM serving plugin.

Wraps a `vLLM <https://github.com/vllm-project/vllm>`_ server with AumOS
attestation checks. Before the server is allowed to serve traffic it must
produce a hardware attestation (GPU TEE / SEV-SNP / TDX / NVIDIA CC) that the
caller can verify; the resulting attestation envelope is exposed via
``get_attestation_envelope`` so downstream clients can refuse to talk to an
un-attested server.

Two run modes are supported:

- ``standalone``: spawns ``python -m vllm.entrypoints.openai.api_server`` as a
  subprocess. Requires ``vllm`` to be importable on the host.
- ``mock``: returns synthetic responses and a synthetic attestation envelope.
  This is the default in tests and in any environment without a real GPU.

Usage:
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/llama-3", gpu_attestation_required=True)
    assert server.health_check() is HealthStatus.HEALTHY
    envelope = server.get_attestation_envelope()
"""

from __future__ import annotations

import hashlib
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import IO, Any, Literal, Protocol, runtime_checkable

RunMode = Literal["standalone", "mock"]


class HealthStatus(str, Enum):
    """Outcome of a health check."""

    HEALTHY = "healthy"  # server up + attestation OK
    UNHEALTHY = "unhealthy"  # server process down or HTTP probe failed
    ATTESTATION_FAILED = "attestation_failed"  # server up but attestation missing/invalid
    NOT_STARTED = "not_started"


@dataclass
class AttestationEnvelope:
    """The attestation artifact produced by a serving instance.

    Real deployments will populate ``quote`` and ``report_data`` with a verifiable
    TEE quote; in mock mode the envelope contains a synthetic, deterministic
    digest derived from the model path and a per-instance nonce.
    """

    model_path: str
    quote: str
    report_data: str
    measurement: str
    produced_at: float
    backend: str  # e.g. "nvidia-cc", "sev-snp", "tdx", "mock"
    verified: bool = False
    digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_path": self.model_path,
            "quote": self.quote,
            "report_data": self.report_data,
            "measurement": self.measurement,
            "produced_at": self.produced_at,
            "backend": self.backend,
            "verified": self.verified,
            "digest": self.digest,
        }


@dataclass
class HealthReport:
    """Detailed outcome of ``health_check``."""

    status: HealthStatus
    server_up: bool
    attestation_ok: bool
    detail: str = ""


def _free_port() -> int:
    """Allocate an ephemeral TCP port for the mock/standalone server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class AttestationUnavailable(RuntimeError):
    """Raised when a real attestation backend is requested but no verifier is wired.

    This is deliberately an exception rather than a ``False`` return. A caller that
    asks for ``nvidia-cc``/``sev-snp``/``tdx`` and silently receives an unverified
    envelope is strictly worse off than one that fails to start: it believes it has
    hardware attestation when it has none. Fail closed, loudly.
    """


@runtime_checkable
class QuoteCollector(Protocol):
    """Collects a platform attestation quote. Supplied by the operator.

    Implementations wrap the real platform verifier -- NVIDIA nvTrust/NRAS, AMD
    SEV-SNP via the KDS/VCEK chain, or Intel TDX. AumOS deliberately ships none:
    binding an NDA-gated or vendor-specific SDK is the deployer's decision.
    """

    def collect(self, model_path: str, nonce: str) -> AttestationEnvelope:
        """Return an envelope whose ``quote`` came from real hardware."""
        ...

    def verify(self, envelope: AttestationEnvelope) -> bool:
        """Verify the quote against the platform's root of trust."""
        ...


def _verify_envelope(
    envelope: AttestationEnvelope,
    collector: QuoteCollector | None = None,
) -> bool:
    """Verify an attestation envelope, failing closed on every unknown path.

    Only the ``mock`` backend is verifiable in-tree, and only by recomputing the
    digest it was built from -- which proves nothing about hardware and is labelled
    as such. Every other backend requires a ``QuoteCollector``.

    Raises:
        AttestationUnavailable: a non-mock backend was requested with no collector.
    """
    if not envelope.quote or not envelope.measurement:
        return False
    if envelope.backend == "mock":
        expected = _mock_digest(envelope.model_path, envelope.report_data)
        return envelope.digest == expected
    if collector is None:
        raise AttestationUnavailable(
            f"attestation_backend={envelope.backend!r} requires a QuoteCollector; "
            "none was supplied. AumOS does not ship a platform verifier -- pass one "
            "via AttestedVLLMServer(quote_collector=...) or use backend='mock' and "
            "treat the result as unattested."
        )
    return bool(collector.verify(envelope))


def _mock_digest(model_path: str, nonce: str) -> str:
    h = hashlib.sha256()
    h.update(model_path.encode("utf-8"))
    h.update(b"|")
    h.update(nonce.encode("utf-8"))
    return "sha256:" + h.hexdigest()


@dataclass
class AttestedVLLMServer:
    """A vLLM server wrapped with AumOS attestation checks.

    Parameters:
        mode:               ``standalone`` (real subprocess) or ``mock``.
        port:               TCP port; ``None`` picks a free port in ``start``.
        host:               bind host for the OpenAI-compatible API.
        attestation_backend: label placed in the attestation envelope.
        request_timeout_s:  per-probe timeout for ``health_check``.
        log_dir:            directory for the vLLM server log. ``None`` uses a
                            per-instance temporary directory.
    """

    mode: RunMode = "mock"
    port: int | None = None
    host: str = "127.0.0.1"
    attestation_backend: str = "mock"
    request_timeout_s: float = 5.0
    log_dir: str | None = None
    # Operator-supplied platform verifier. REQUIRED for any non-mock backend.
    quote_collector: QuoteCollector | None = None
    # Populated by start()
    _model_path: str = ""
    _gpu_attestation_required: bool = False
    _process: subprocess.Popen | None = None
    _log_path: Path | None = None
    _log_handle: IO[bytes] | None = None
    _started_at: float = 0.0
    _envelope: AttestationEnvelope | None = None
    _instance_nonce: str = field(default_factory=lambda: secrets.token_hex(16))

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(
        self,
        model_path: str,
        gpu_attestation_required: bool = False,
    ) -> None:
        """Start the vLLM server (or mock) and capture an attestation envelope.

        Raises ``RuntimeError`` if the server is already running or, in
        standalone mode, if ``vllm`` is not installed.
        """
        if self._process is not None or self._envelope is not None:
            raise RuntimeError("server already started; call stop() first")
        if not model_path:
            raise ValueError("model_path must be a non-empty string")
        if self.port is None:
            self.port = _free_port()
        self._model_path = model_path
        self._gpu_attestation_required = gpu_attestation_required
        self._started_at = time.time()

        if self.mode == "standalone":
            self._start_standalone()
        elif self.mode == "mock":
            self._start_mock()
        else:  # pragma: no cover - defensive
            raise ValueError(f"unknown mode {self.mode!r}")

        self._envelope = self._collect_attestation()

    def _vllm_importable(self) -> bool:
        """Import-test vllm in a subprocess so this package does NOT take vllm
        as a hard dependency. Overridable for tests."""
        probe = subprocess.run(
            [sys.executable, "-c", "import vllm"],
            capture_output=True,
            check=False,
        )
        return probe.returncode == 0

    def _build_command(self) -> list[str]:
        """The argv used to launch vLLM. Overridable so tests can drive the
        real spawn/redirect path without installing vllm."""
        return [
            sys.executable,
            "-m",
            "vllm.entrypoints.openai.api_server",
            "--model",
            self._model_path,
            "--host",
            self.host,
            "--port",
            str(self.port),
        ]

    def _start_standalone(self) -> None:
        """Spawn ``python -m vllm.entrypoints.openai.api_server``."""
        if shutil.which("python") is None and sys.executable == "":
            raise RuntimeError("no python interpreter available to launch vllm")
        if not self._vllm_importable():
            raise RuntimeError("vllm is not installed; install it or use mode='mock'")
        cmd = self._build_command()
        # vLLM writes a large volume of progress output while loading weights.
        # Piping it without a reader would fill the OS pipe buffer (as little as
        # 4 KiB on some platforms) and block the child forever, so the server
        # would never finish binding its port. Redirect to a file instead: the
        # kernel never blocks the writer, and the output stays available for
        # diagnosing startup failures.
        base = Path(self.log_dir) if self.log_dir else Path(tempfile.gettempdir())
        base.mkdir(parents=True, exist_ok=True)
        self._log_path = base / f"vllm-{self.port}-{self._instance_nonce}.log"
        self._log_handle = self._log_path.open("wb")
        try:
            # Subprocess args are all controlled (no shell). Suppressed S603 accordingly.
            self._process = subprocess.Popen(
                cmd,
                stdout=self._log_handle,
                stderr=subprocess.STDOUT,
            )
        except OSError:
            self._close_log()
            raise

    def _start_mock(self) -> None:
        """In mock mode there is no real subprocess; we just mark started."""
        self._process = None  # type: ignore[assignment]

    def _close_log(self) -> None:
        """Close the server log handle. The file itself is left on disk."""
        handle = self._log_handle
        self._log_handle = None
        if handle is not None:
            handle.close()

    @property
    def server_log_path(self) -> Path | None:
        """Path to this instance's vLLM log, or ``None`` in mock mode."""
        return self._log_path

    def read_server_log(self, max_bytes: int = 8192) -> str:
        """Return the tail of the server log — the first place to look when
        ``start`` succeeds but the server never becomes healthy."""
        path = self._log_path
        if path is None or not path.exists():
            return ""
        with path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            return handle.read().decode("utf-8", errors="replace")

    def stop(self) -> None:
        """Terminate the server (if running). Safe to call when not started."""
        proc = self._process
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        self._close_log()
        self._process = None
        self._envelope = None
        self._started_at = 0.0

    # ------------------------------------------------------------------
    # Attestation
    # ------------------------------------------------------------------
    def _collect_attestation(self) -> AttestationEnvelope:
        """Produce an attestation envelope for the running instance."""
        if self.attestation_backend == "mock":
            nonce = self._instance_nonce
            digest = _mock_digest(self._model_path, nonce)
            env = AttestationEnvelope(
                model_path=self._model_path,
                quote=f"mock-quote:{nonce}",
                report_data=nonce,
                measurement=f"mock-measurement:{digest[:16]}",
                produced_at=time.time(),
                backend="mock",
                digest=digest,
            )
            env.verified = _verify_envelope(env)
            return env

        # A real backend MUST come from a real collector. Previously this branch
        # fabricated `f"{backend}-quote:{nonce}"` and `f"{backend}-measurement:..."`
        # itself and then "verified" them by checking both strings were non-empty --
        # so any caller setting attestation_backend="nvidia-cc" received
        # verified=True over a quote this process had just invented. Fail closed.
        if self.quote_collector is None:
            raise AttestationUnavailable(
                f"attestation_backend={self.attestation_backend!r} requires a "
                "QuoteCollector; none was supplied. Pass "
                "AttestedVLLMServer(quote_collector=...) with a real platform "
                "verifier, or use backend='mock' and treat the result as unattested."
            )
        nonce = self._instance_nonce
        env = self.quote_collector.collect(self._model_path, nonce)
        if env.backend != self.attestation_backend:
            raise AttestationUnavailable(
                f"collector returned backend={env.backend!r} but server was "
                f"configured for {self.attestation_backend!r}"
            )
        if env.report_data != nonce:
            raise AttestationUnavailable(
                "collector returned an envelope not bound to this instance nonce; "
                "the quote may be replayed from another instance"
            )
        env.verified = _verify_envelope(env, self.quote_collector)
        if not env.verified:
            raise AttestationUnavailable(f"platform verifier rejected the {env.backend} quote")
        return env

    def get_attestation_envelope(self) -> AttestationEnvelope:
        """Return the attestation envelope for this instance.

        Raises ``RuntimeError`` if the server has not been started.
        """
        if self._envelope is None:
            raise RuntimeError("server not started; call start() first")
        return self._envelope

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------
    def _server_up(self) -> tuple[bool, str]:
        """Probe the OpenAI-compatible API ``/health`` or ``/v1/models``."""
        if self.mode == "mock":
            # Mock is always "up" once start() has been called.
            return True, "mock server up"
        proc = self._process
        if proc is None or proc.poll() is not None:
            detail = "vllm subprocess not running"
            if proc is not None:
                detail = f"{detail} (exit={proc.returncode})"
            tail = self.read_server_log(max_bytes=2048).strip()
            if tail:
                detail = f"{detail}; last log output:\n{tail}"
            return False, detail
        # In standalone mode we'd issue an HTTP request here. We use the
        # standard library only to avoid a hard dep on ``requests``.
        import urllib.request
        from urllib.error import URLError

        url = f"http://{self.host}:{self.port}/health"
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=self.request_timeout_s) as resp:
                ok = resp.status == 200
            return ok, "vllm /health status=200"
        except (URLError, OSError, TimeoutError) as exc:
            return False, f"vllm /health probe failed: {exc}"

    def health_check(self) -> HealthStatus:
        """High-level health: ``HEALTHY`` only if server up AND attestation OK."""
        report = self.detailed_health_check()
        return report.status

    def detailed_health_check(self) -> HealthReport:
        """Detailed health including attestation state."""
        if self._envelope is None and self._process is None:
            return HealthReport(
                status=HealthStatus.NOT_STARTED,
                server_up=False,
                attestation_ok=False,
                detail="server not started",
            )
        server_up, detail = self._server_up()
        if not server_up:
            return HealthReport(
                status=HealthStatus.UNHEALTHY,
                server_up=False,
                attestation_ok=False,
                detail=detail,
            )
        if self._gpu_attestation_required:
            env = self._envelope
            if env is None or not env.verified:
                return HealthReport(
                    status=HealthStatus.ATTESTATION_FAILED,
                    server_up=True,
                    attestation_ok=False,
                    detail="attestation required but missing/invalid",
                )
        return HealthReport(
            status=HealthStatus.HEALTHY,
            server_up=True,
            attestation_ok=True,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Inference helpers (mock)
    # ------------------------------------------------------------------
    def mock_complete(self, prompt: str) -> dict[str, Any]:
        """Return a synthetic OpenAI-style completion (mock mode only)."""
        if self.mode != "mock" or self._envelope is None:
            raise RuntimeError("mock_complete requires mode='mock' and start()")
        digest = self._envelope.digest
        return {
            "id": f"mock-{self._instance_nonce[:8]}",
            "object": "chat.completion",
            "model": self._model_path,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"[attested:{digest[:12]}] echo: {prompt}",
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": len(prompt.split()),
                "completion_tokens": 4,
                "total_tokens": len(prompt.split()) + 4,
            },
        }

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------
    def __enter__(self) -> AttestedVLLMServer:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()


__all__ = [
    "AttestationEnvelope",
    "AttestationUnavailable",
    "AttestedVLLMServer",
    "HealthReport",
    "HealthStatus",
    "QuoteCollector",
    "RunMode",
]

"""AumOS bridge-rt (N2) — unified inference backend abstraction.

Provides a single ``generate()`` API that auto-selects the best available backend
(TensorRT-LLM > vLLM > Ollama) and handles the **TensorRT-LLM v0.16 breaking change**: the
``sampler_type`` argument became required and the C++ TRTLLM sampler became the default. BridgeRT
detects the version at runtime and adapts (per cross-cutting 11-nvidia-compatibility-matrix).

See ``docs/rfcs/N2-bridge-rt.md``.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class Backend(str, Enum):
    """Supported backends, in preference order."""

    TENSORRT_LLM = "tensorrt-llm"
    VLLM = "vllm"
    OLLAMA = "ollama"
    MOCK = "mock"


# Preference order — first available wins (per RFC N2).
PREFERENCE: list[Backend] = [Backend.TENSORRT_LLM, Backend.VLLM, Backend.OLLAMA, Backend.MOCK]


@dataclass
class GenerateRequest:
    """A unified generate request (backend-agnostic)."""

    model: str
    prompt: str
    max_tokens: int = 128
    temperature: float = 1.0
    top_p: float = 1.0


@dataclass
class GenerateResponse:
    """A unified generate response."""

    text: str
    backend: Backend
    backend_version: str = ""
    sampler_type_adapted: bool = False  # True if BridgeRT adapted for TRT-LLM v0.16


class BackendImpl(Protocol):
    """The interface every backend implements."""

    name: Backend

    def is_available(self) -> bool: ...
    def version(self) -> str: ...
    def generate(self, req: GenerateRequest) -> GenerateResponse: ...


# ---------------------------------------------------------------------------
# TRT-LLM v0.16 sampler_type compatibility logic.
# ---------------------------------------------------------------------------
# In TRT-LLM < 0.16, no sampler_type arg was needed. In v0.16, the default C++ TRTLLM sampler
# became the default and the arg is required to select alternatives (e.g. "logits_post_processor").
# BridgeRT detects the version and injects the correct sampler_type.

# Anything >= 0.16 requires the sampler_type arg.
_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def _parse_version(v: str) -> tuple[int, int]:
    """Parse a 'major.minor[.patch]' string into a (major, minor) tuple. Returns (0, 0) on
    failure."""
    m = _VERSION_RE.search(v or "")
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


def needs_sampler_type(version: str) -> bool:
    """True if the TRT-LLM version requires the sampler_type argument (>= 0.16)."""
    major, minor = _parse_version(version)
    return (major, minor) >= (0, 16)


def adapt_for_trt_llm(req: GenerateRequest, version: str) -> dict[str, Any]:
    """Translate a GenerateRequest into TRT-LLM kwargs, injecting sampler_type if needed."""
    kwargs: dict[str, Any] = {
        "max_tokens": req.max_tokens,
        "temperature": req.temperature,
        "top_p": req.top_p,
    }
    if needs_sampler_type(version):
        # The C++ TRTLLM sampler is the v0.16 default; we request it explicitly so behavior
        # is identical across versions.
        kwargs["sampler_type"] = "trtllm"
    return kwargs


# ---------------------------------------------------------------------------
# Built-in backend implementations. v1.0 ships the Mock + a CLI-probe-style
# "is_available" check that shells out to the backend's --version. Real
# in-process backends land in task 03.
# ---------------------------------------------------------------------------
class MockBackend:
    """Deterministic backend for CI / development."""

    name = Backend.MOCK

    def is_available(self) -> bool:
        return True

    def version(self) -> str:
        return "mock-1.0.0"

    def generate(self, req: GenerateRequest) -> GenerateResponse:
        return GenerateResponse(
            text=f"[mock] {req.prompt[:32]}",
            backend=self.name,
            backend_version=self.version(),
        )


class CliProbeBackend:
    """A backend whose availability is probed by shelling out to ``binary --version``.
    Used for vLLM, Ollama, and TRT-LLM (which all expose a CLI). The actual generate() is
    delegated to a caller-supplied function in production; v1.0 returns an error response
    if generate() is called directly (it's expected that N1 open-serve-kit routes via HTTP
    instead)."""

    def __init__(
        self,
        name: Backend,
        binary: str,
        generate_fn: Callable[[GenerateRequest], GenerateResponse] | None = None,
    ) -> None:
        self.name = name
        self.binary = binary
        self._generate_fn = generate_fn

    def is_available(self) -> bool:
        try:
            subprocess.run([self.binary, "--version"], capture_output=True, timeout=5, check=False)
            return True
        except (OSError, subprocess.SubprocessError):
            return False

    def version(self) -> str:
        try:
            r = subprocess.run(
                [self.binary, "--version"], capture_output=True, timeout=5, text=True, check=False
            )
            return (r.stdout or r.stderr or "").strip() or "unknown"
        except (OSError, subprocess.SubprocessError):
            return "unknown"

    def generate(self, req: GenerateRequest) -> GenerateResponse:
        if self._generate_fn is None:
            raise RuntimeError(
                f"{self.name.value}: CliProbeBackend.generate not configured; route via N1 open-serve-kit HTTP instead"
            )
        return self._generate_fn(req)


def _default_registry() -> dict[Backend, BackendImpl]:
    return {
        Backend.TENSORRT_LLM: CliProbeBackend(Backend.TENSORRT_LLM, "trtllm-bench"),
        Backend.VLLM: CliProbeBackend(Backend.VLLM, "vllm"),
        Backend.OLLAMA: CliProbeBackend(Backend.OLLAMA, "ollama"),
        Backend.MOCK: MockBackend(),
    }


@dataclass
class Bridge:
    """Selects a backend and routes generate() calls."""

    registry: dict[Backend, BackendImpl] = field(default_factory=_default_registry)
    forced: Backend | None = None  # if set, always use this backend

    def force(self, backend: Backend) -> Bridge:
        """Pin the bridge to a specific backend (skips auto-selection)."""
        self.forced = backend
        return self

    def select(self) -> BackendImpl:
        """Return the highest-preference available backend."""
        if self.forced is not None:
            impl = self.registry.get(self.forced)
            if impl is None or not impl.is_available():
                raise RuntimeError(f"forced backend {self.forced.value} not available")
            return impl
        for candidate in PREFERENCE:
            impl = self.registry.get(candidate)
            if impl is not None and impl.is_available():
                return impl
        raise RuntimeError("no backend available")

    def generate(self, req: GenerateRequest) -> GenerateResponse:
        """Generate using the selected backend."""
        impl = self.select()
        resp = impl.generate(req)
        # If TRT-LLM was used, mark whether sampler_type adaptation happened.
        if resp.backend is Backend.TENSORRT_LLM:
            resp.sampler_type_adapted = needs_sampler_type(resp.backend_version)
        return resp


def generate(req: GenerateRequest, bridge: Bridge | None = None) -> GenerateResponse:
    """Convenience: generate with the default bridge."""
    return (bridge or Bridge()).generate(req)


__all__ = [
    "PREFERENCE",
    "Backend",
    "BackendImpl",
    "Bridge",
    "CliProbeBackend",
    "GenerateRequest",
    "GenerateResponse",
    "MockBackend",
    "adapt_for_trt_llm",
    "generate",
    "needs_sampler_type",
]

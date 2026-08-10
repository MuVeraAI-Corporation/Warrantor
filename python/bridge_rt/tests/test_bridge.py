"""Tests for bridge_rt: version detection, sampler_type adaptation, backend selection, CLI."""

from __future__ import annotations

import json

import pytest

from bridge_rt import (
    Backend,
    Bridge,
    GenerateRequest,
    MockBackend,
    adapt_for_trt_llm,
    needs_sampler_type,
)
from bridge_rt.cli import main


# --- Version detection & sampler_type adaptation -----------------------------
@pytest.mark.parametrize(
    "version,expected",
    [
        ("0.15.0", False),
        ("0.16.0", True),
        ("0.16.1", True),
        ("1.0.0", True),
        ("0.14", False),
        ("garbage", False),
        ("", False),
    ],
)
def test_needs_sampler_type(version: str, expected: bool) -> None:
    assert needs_sampler_type(version) is expected


def test_adapt_for_trt_llm_below_v016_omits_sampler_type() -> None:
    req = GenerateRequest(model="m", prompt="hi")
    kwargs = adapt_for_trt_llm(req, "0.15.0")
    assert "sampler_type" not in kwargs


def test_adapt_for_trt_llm_at_v016_injects_sampler_type() -> None:
    req = GenerateRequest(model="m", prompt="hi")
    kwargs = adapt_for_trt_llm(req, "0.16.0")
    assert kwargs["sampler_type"] == "trtllm"


# --- Backend selection -------------------------------------------------------
def test_bridge_force_selects_mock() -> None:
    """Forcing Mock bypasses auto-selection — deterministic for tests."""
    bridge = Bridge().force(Backend.MOCK)
    impl = bridge.select()
    assert impl.name is Backend.MOCK


def test_bridge_force_overrides_selection() -> None:
    bridge = Bridge().force(Backend.MOCK)
    assert bridge.select().name is Backend.MOCK


def test_bridge_force_unavailable_raises() -> None:
    # Force a backend that exists in the registry but is unavailable.
    bridge = Bridge().force(Backend.VLLM)  # vllm almost certainly unavailable in CI
    if not bridge.registry[Backend.VLLM].is_available():
        with pytest.raises(RuntimeError, match="not available"):
            bridge.select()


def test_generate_via_mock() -> None:
    bridge = Bridge().force(Backend.MOCK)
    resp = bridge.generate(GenerateRequest(model="m", prompt="hello"))
    assert resp.backend is Backend.MOCK
    assert "hello" in resp.text


# --- CLI ---------------------------------------------------------------------
def test_cli_probe(capsys: pytest.CaptureFixture[str]) -> int | None:
    rc = main(["probe"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "mock" in out
    return rc


def test_cli_probe_json(capsys: pytest.CaptureFixture[str]) -> int | None:
    rc = main(["probe", "--json"])
    assert rc == 0
    rows = json.loads(capsys.readouterr().out)
    assert any(r["backend"] == "mock" and r["available"] for r in rows)
    return rc


def test_cli_generate(capsys: pytest.CaptureFixture[str]) -> int | None:
    rc = main(["generate", "--model", "m", "--prompt", "hi", "--force", "mock"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["backend"] == "mock"
    assert "hi" in out["text"]
    return rc


def test_mock_backend_is_always_available() -> None:
    assert MockBackend().is_available()

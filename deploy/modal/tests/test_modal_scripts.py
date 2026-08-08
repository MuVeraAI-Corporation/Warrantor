"""Stub-based validation for the AumOS Modal scripts.

The Modal scripts (``safe_eval_modal.py`` / ``adversaria_modal.py``) run inside
Modal's cloud and require the real ``modal`` and ``vllm`` packages, which are
not available in CI / locally. This test fakes those two packages with minimal
stubs that record the decorator calls and let the in-process runner functions
execute against a fake model. The goal is to catch API drift between the scripts
and the real AumOS ``safe_eval`` / ``adversaria`` packages *before* a deploy.

What this validates:
  - the scripts import cleanly,
  - the decorator usage (``@app.function``, ``@app.cls``, ``@modal.enter()``,
    ``@modal.method()``, ``@app.local_entrypoint``) matches the stub's contract
    (which mirrors the real Modal API shape),
  - ``run_safe_eval`` produces a well-formed JSON dict whose ``pipeline`` field
    matches ``safe_eval.PipelineResult.to_dict()``,
  - ``run_adversaria`` produces a well-formed summary whose per-attack-type
    breakdown covers all five built-in attack types,
  - the image-build directives (``pip_install``, ``add_local_dir``, etc.) are
    well-formed.

What this does NOT validate: actual GPU inference (the fake model returns a
fixed string), real Modal networking, and real vLLM behaviour.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
MODAL_DIR = REPO_ROOT / "deploy" / "modal"


# ---------------------------------------------------------------------------
# Fake `modal` package — mirrors the API surface the scripts use.
# ---------------------------------------------------------------------------


class _FakeImage:
    def __init__(self) -> None:
        self.steps: list[str] = []

    @classmethod
    def from_registry(cls, *args: object, **kwargs: object) -> "_FakeImage":
        inst = cls()
        inst.steps.append(f"from_registry({args}, {kwargs})")
        return inst

    def entrypoint(self, val: object) -> "_FakeImage":
        self.steps.append(f"entrypoint({val!r})")
        return self

    def pip_install(self, *pkgs: str) -> "_FakeImage":
        self.steps.append(f"pip_install({pkgs})")
        return self

    def uv_pip_install(self, *pkgs: str) -> "_FakeImage":
        self.steps.append(f"uv_pip_install({pkgs})")
        return self

    def run_commands(self, *cmds: str) -> "_FakeImage":
        self.steps.append(f"run_commands({cmds})")
        return self

    def add_local_dir(self, src: str, dst: str) -> "_FakeImage":
        self.steps.append(f"add_local_dir({src!r}, {dst!r})")
        return self

    def env(self, mapping: object) -> "_FakeImage":
        self.steps.append(f"env({mapping})")
        return self


class _FakeMethod:
    """Stand-in for a @modal.method()-decorated method."""

    def __init__(self, func):
        self.func = func

    def __call__(self, *a, **k):
        return self.func(*a, **k)


class _FakeFunction:
    def __init__(self, func, **kwargs):
        self.func = func
        self.kwargs = kwargs

    def __call__(self, *a, **k):
        return self.func(*a, **k)

    @property
    def remote(self):
        # Calling .remote() should execute locally in this stub.
        return self.func


class _FakeCls:
    def __init__(self, **kwargs):
        self.kwargs = kwargs

    def __call__(self, cls):
        # Wrap the class so instantiation works; store kwargs for inspection.
        cls._modal_kwargs = self.kwargs
        return cls


class _FakeApp:
    def __init__(self, name, image=None):
        self.name = name
        self.image = image
        self.functions: list[str] = []
        self.classes: list[str] = []
        self.entrypoints: list[str] = []

    def function(self, **kwargs):
        def deco(func):
            self.functions.append(func.__name__)
            return _FakeFunction(func, **kwargs)

        return deco

    def cls(self, **kwargs):
        fake = _FakeCls(**kwargs)
        orig_call = fake.__call__

        def tracking_call(cls):
            self.classes.append(cls.__name__)
            return orig_call(cls)

        fake.__call__ = tracking_call
        return fake

    def local_entrypoint(self, *a, **k):
        def deco(func):
            self.entrypoints.append(func.__name__)
            return func

        return deco


def _make_modal_module() -> types.ModuleType:
    m = types.ModuleType("modal")

    def app_factory(name, image=None):
        app = _FakeApp(name, image)
        _MODAL_STATE["apps"].append(app)
        return app

    m.App = app_factory  # type: ignore[attr-defined]

    def image_from_registry(*a, **k):
        return _FakeImage.from_registry(*a, **k)

    m.Image = types.SimpleNamespace(from_registry=image_from_registry)  # type: ignore[attr-defined]

    def enter_deco(*a, **k):
        def deco(func):
            return func

        return deco

    m.enter = enter_deco  # type: ignore[attr-defined]

    def method_deco(*a, **k):
        def deco(func):
            return _FakeMethod(func)

        return deco

    m.method = method_deco  # type: ignore[attr-defined]

    def exit_deco(*a, **k):
        def deco(func):
            return func

        return deco

    m.exit = exit_deco  # type: ignore[attr-defined]

    _MODAL_STATE["image_steps"] = []
    return m


_MODAL_STATE: dict = {"apps": [], "image_steps": []}

# ---------------------------------------------------------------------------
# Fake `vllm` package
# ---------------------------------------------------------------------------


class _FakeSamplingParams:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class _FakeOutput:
    def __init__(self, text: str):
        self.text = text


class _FakeRequestOutput:
    def __init__(self, text: str):
        self.outputs = [_FakeOutput(text)]


class _FakeLLM:
    """A vllm.LLM stand-in that returns a canned response for any prompt.

    The canned response contains refusal markers so adversaria's conservative
    detectors will classify most attacks as failed (target behaved safely) —
    which is what we want to assert against.
    """

    canned = "I can't comply with that request."

    def __init__(self, *a, **k):
        self.init_args = a
        self.init_kwargs = k

    def generate(self, prompts, params=None):
        return [_FakeRequestOutput(self.canned) for _ in prompts]


def _make_vllm_module() -> types.ModuleType:
    m = types.ModuleType("vllm")
    m.LLM = _FakeLLM  # type: ignore[attr-defined]
    m.SamplingParams = _FakeSamplingParams  # type: ignore[attr-defined]
    return m


# ---------------------------------------------------------------------------
# pytest fixtures: install fakes, load the scripts as modules.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def safe_eval_modal():
    _MODAL_STATE["apps"].clear()
    sys.modules["modal"] = _make_modal_module()
    sys.modules["vllm"] = _make_vllm_module()
    spec = importlib.util.spec_from_file_location(
        "safe_eval_modal", MODAL_DIR / "safe_eval_modal.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def adversaria_modal():
    _MODAL_STATE["apps"].clear()
    sys.modules["modal"] = _make_modal_module()
    sys.modules["vllm"] = _make_vllm_module()
    spec = importlib.util.spec_from_file_location(
        "adversaria_modal", MODAL_DIR / "adversaria_modal.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# safe_eval_modal tests
# ---------------------------------------------------------------------------


def test_safe_eval_app_uses_a10g_gpu(safe_eval_modal):
    apps = _MODAL_STATE["apps"]
    assert len(apps) == 1
    app = apps[0]
    assert app.name.startswith("aumos-safe-eval")
    # The runner function requested the A10G GPU.
    assert any("run_safe_eval" in f for f in app.functions)


def test_safe_eval_image_installs_vllm_and_local_pkg(safe_eval_modal):
    img = safe_eval_modal.image
    joined = " ".join(img.steps)
    assert "vllm" in joined
    assert "safe_eval" in joined
    assert "add_local_dir" in joined


def test_run_safe_eval_returns_well_formed_pipeline(safe_eval_modal):
    result = safe_eval_modal.run_safe_eval(
        model_name="facebook/opt-1.3b",
        prompts=["The capital of France is"],
        max_tokens=8,
    )
    assert result["model"] == "facebook/opt-1.3b"
    assert result["prompt_count"] == 1
    assert len(result["generations"]) == 1
    # pipeline.to_dict() shape
    pipe = result["pipeline"]
    assert pipe["target"] == "facebook/opt-1.3b"
    assert "run_id" in pipe
    assert "stages" in pipe
    assert pipe["stages"][0]["type"] == "benchmarks"
    assert pipe["stages"][0]["adapter"] == "inline"
    # The inline adapter reports the completed-prompts metric.
    metric_names = {m["name"] for m in pipe["stages"][0]["metrics"]}
    assert "prompts_completed" in metric_names
    # A VEB is attached.
    assert result["veb"]["model"] == "facebook/opt-1.3b"


def test_run_safe_eval_default_prompts_used_when_none(safe_eval_modal):
    result = safe_eval_modal.run_safe_eval()
    # The default prompt set has 4 probes.
    assert result["prompt_count"] == 4


# ---------------------------------------------------------------------------
# adversaria_modal tests
# ---------------------------------------------------------------------------


def test_adversaria_app_registered(adversaria_modal):
    apps = _MODAL_STATE["apps"]
    assert len(apps) == 1
    app = apps[0]
    assert app.name.startswith("aumos-adversaria")
    assert any("run_adversaria" in f for f in app.functions)


def test_adversaria_image_installs_vllm_and_local_pkg(adversaria_modal):
    img = adversaria_modal.image
    joined = " ".join(img.steps)
    assert "vllm" in joined
    assert "adversaria" in joined


def test_run_adversaria_covers_all_five_attack_types(adversaria_modal):
    result = adversaria_modal.run_adversaria(
        model_name="facebook/opt-1.3b", prompts_per_attack=1, max_tokens=8
    )
    assert result["model"] == "facebook/opt-1.3b"
    assert result["attack_count"] == 5
    by_type = set(result["by_attack_type"].keys())
    assert by_type == {
        "prompt_injection",
        "jailbreak",
        "encoding_attack",
        "multi_turn_manipulation",
        "training_data_extraction",
    }
    # The fake model always refuses, so every attack must be classified as
    # failed (success_count == 0) — i.e. the target behaved safely.
    assert result["success_count"] == 0
    assert result["overall_success_rate"] == 0.0
    # Per-type success rates all zero.
    for rate in result["success_rate_by_attack_type"].values():
        assert rate == 0.0
    # Full result list present.
    assert len(result["results"]) == 5
    for r in result["results"]:
        assert "prompt" in r and "response" in r and "severity" in r


def test_run_adversaria_prompts_per_attack_scales_count(adversaria_modal):
    result = adversaria_modal.run_adversaria(prompts_per_attack=2, max_tokens=4)
    assert result["attack_count"] == 10  # 5 attack types * 2 prompts each
    assert len(result["results"]) == 10

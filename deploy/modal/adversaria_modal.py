"""Modal deployment for AumOS adversaria attacks against a vLLM-served model.

Deploys a Modal function that runs the five built-in adversaria attack
generators (``PromptInjection``, ``Jailbreak``, ``EncodingAttack``,
``MultiTurnManipulation``, ``TrainingDataExtraction``) against a model served
on Modal via vLLM, and reports per-attack-type success rates.

The adversaria package is installed into the container image from the local
source tree, so the deployed function runs the *real* AumOS attack suite — not
a mock. The model is wrapped in a small ``Target`` adapter (implementing
adversaria's ``Target.respond(prompt) -> str`` protocol) that drives the
in-process ``vllm.LLM`` engine, so attacks exercise the real model rather than
a stub.

Deploy / run:

    # one-time
    modal token set

    # run locally (spins the GPU container, runs all five attacks, prints JSON)
    modal run deploy/modal/adversaria_modal.py

    # deploy as a pinned, callable function
    modal deploy deploy/modal/adversaria_modal.py

Configuration via env vars (all optional):

    AUMOS_MODAL_MODEL    default "facebook/opt-1.3b"
    AUMOS_MODAL_GPU      default "A10G"   (any Modal GPU spec, e.g. "L4:1")
    AUMOS_MODAL_MAX_TOKENS  default 64
    AUMOS_MODAL_PROMPTS_PER_ATTACK  default 1
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Modal app + image
# ---------------------------------------------------------------------------
import modal

APP_NAME = "aumos-adversaria"

MODEL_NAME = os.environ.get("AUMOS_MODAL_MODEL", "facebook/opt-1.3b")
GPU_SPEC = os.environ.get("AUMOS_MODAL_GPU", "A10G")
MAX_TOKENS = int(os.environ.get("AUMOS_MODAL_MAX_TOKENS", "64"))
PROMPTS_PER_ATTACK = int(os.environ.get("AUMOS_MODAL_PROMPTS_PER_ATTACK", "1"))

_REPO_ROOT = Path(__file__).resolve().parents[2]
_ADVERSARIA_SRC = _REPO_ROOT / "python" / "adversaria"

image = (
    modal.Image.from_registry(
        "nvidia/cuda:12.9.0-devel-ubuntu22.04", add_python="3.12"
    )
    .entrypoint([])
    .pip_install("vllm==0.11.0", "torch==2.8.0")
    .add_local_dir(str(_ADVERSARIA_SRC), "/root/adversaria")
    .run_commands("pip install -e /root/adversaria")
)

app = modal.App(APP_NAME, image=image)


# ---------------------------------------------------------------------------
# GPU model server
# ---------------------------------------------------------------------------
@app.cls(gpu=GPU_SPEC, container_idle_timeout=300, timeout=60 * 30)
class VLLMModel:
    """A vLLM-served model running on an A10G GPU.

    Loaded once per container in ``setup`` so repeated calls reuse the warmed
    engine. ``respond`` implements the adversaria ``Target`` protocol so an
    ``AttackSuite`` can drive it directly.
    """

    model_name: str = MODEL_NAME

    @modal.enter()
    def setup(self) -> None:
        from vllm import LLM

        self.llm = LLM(model=self.model_name, enforce_eager=False)

    @modal.method()
    def generate(self, prompts: list[str], max_tokens: int = MAX_TOKENS) -> list[str]:
        """Batched generation entrypoint (one completion per prompt, in order)."""
        from vllm import SamplingParams

        params = SamplingParams(max_tokens=max_tokens, temperature=0.0)
        outputs = self.llm.generate(prompts, params)
        return [o.outputs[0].text for o in outputs]

    @modal.method()
    def respond(self, prompt: str) -> str:
        """adversaria Target protocol: single-prompt generation.

        (We forward to :meth:`generate` one-at-a-time. For high-throughput
        fuzzing, batch via :meth:`generate` instead.)
        """
        return self.generate([prompt])[0]

    @modal.method()
    def health(self) -> dict[str, Any]:
        return {"status": "ok", "model": self.model_name, "gpu": GPU_SPEC}


# ---------------------------------------------------------------------------
# adversaria runner
# ---------------------------------------------------------------------------
def _summary_to_dict(summary: Any) -> dict[str, Any]:
    """Flatten an adversaria.RunSummary to a JSON-serialisable dict."""
    by_type: dict[str, dict[str, int]] = {}
    for r in summary.results:
        key = r.prompt.attack_type.value
        bucket = by_type.setdefault(key, {"attempts": 0, "successes": 0})
        bucket["attempts"] += 1
        if r.succeeded:
            bucket["successes"] += 1
    rates = {
        k: (v["successes"] / v["attempts"]) if v["attempts"] else 0.0
        for k, v in by_type.items()
    }
    return {
        "run_id": summary.run_id,
        "started_at": summary.started_at,
        "attack_count": summary.attack_count,
        "success_count": summary.success_count,
        "overall_success_rate": summary.success_rate,
        "by_attack_type": by_type,
        "success_rate_by_attack_type": rates,
        "critical_or_high_count": len(summary.critical_or_high),
        "results": [
            {
                "attack_type": r.prompt.attack_type.value,
                "succeeded": r.succeeded,
                "severity": r.severity.value,
                "prompt": r.prompt.text,
                "response": r.response,
                "detail": r.detail,
            }
            for r in summary.results
        ],
    }


@app.function(gpu=GPU_SPEC, timeout=60 * 30)
def run_adversaria(
    model_name: str = MODEL_NAME,
    prompts_per_attack: int = PROMPTS_PER_ATTACK,
    max_tokens: int = MAX_TOKENS,
) -> dict[str, Any]:
    """Run the five built-in adversaria attack generators against ``model_name``.

    Loads the model with vLLM on this GPU, wraps it in a ``Target`` adapter,
    builds an ``AttackSuite`` with ``prompts_per_attack`` prompts of each of
    the five built-in attack types, runs the suite, and returns the per-type
    success rates plus the full result list.
    """
    import adversaria as adv  # type: ignore[import-not-found]
    from vllm import LLM, SamplingParams

    llm = LLM(model=model_name, enforce_eager=False)
    sampling = SamplingParams(max_tokens=max_tokens, temperature=0.0)

    class _VLLMTarget:
        """adversaria ``Target`` adapter around the in-process vLLM engine."""

        def respond(self, prompt: str) -> str:
            out = llm.generate([prompt], sampling)
            return out[0].outputs[0].text

    target = _VLLMTarget()

    suite = adv.AttackSuite()
    for attack_type in adv.AttackType:
        if attack_type == adv.AttackType.CUSTOM:
            continue
        suite.add(attack_type, prompts_per_attack)

    summary = suite.run(target)
    return {
        "model": model_name,
        "gpu": GPU_SPEC,
        "prompts_per_attack": prompts_per_attack,
        **_summary_to_dict(summary),
    }


# ---------------------------------------------------------------------------
# Local entrypoint
# ---------------------------------------------------------------------------
@app.local_entrypoint()
def main(
    model: str = MODEL_NAME,
    prompts_per_attack: int = PROMPTS_PER_ATTACK,
    max_tokens: int = MAX_TOKENS,
) -> None:
    """Run the five adversaria attacks and print the results as JSON.

    Usage::

        modal run deploy/modal/adversaria_modal.py
        modal run deploy/modal/adversaria_modal.py --prompts-per-attack 3
    """
    result = run_adversaria.remote(
        model_name=model,
        prompts_per_attack=prompts_per_attack,
        max_tokens=max_tokens,
    )
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")

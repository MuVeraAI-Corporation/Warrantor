"""Modal deployment for AumOS safe-eval against a vLLM-served model on an A10G GPU.

Deploys a Modal function that:

  1. spins up an A10G GPU container with vLLM and a small model
     (``facebook/opt-1.3b`` by default — fits comfortably in 24 GB),
  2. loads the model once per container via ``@modal.enter()`` so cold starts
     amortize the weight download,
  3. runs the AumOS safe-eval benchmark pipeline against it, and
  4. returns the results as a JSON-serialisable dict (a flat representation of
     ``safe_eval.PipelineResult``).

The safe-eval package is installed into the container image from the local
source tree, so the deployed function runs the *real* AumOS pipeline — not a
mock. The model is addressed through the in-process ``vllm.LLM`` /
``llm.generate()`` API (no HTTP hop), which is the highest-throughput way to
drive vLLM from a single client.

Deploy / run:

    # one-time
    modal token set

    # run locally (spins the container, runs the pipeline, prints JSON)
    modal run deploy/modal/safe_eval_modal.py

    # deploy as a pinned, callable function
    modal deploy deploy/modal/safe_eval_modal.py

Configuration via env vars (all optional):

    AUMOS_MODAL_MODEL    default "facebook/opt-1.3b"
    AUMOS_MODAL_GPU      default "A10G"   (any Modal GPU spec, e.g. "L4:1")
    AUMOS_MODAL_MAX_TOKENS  default 64
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

APP_NAME = "warrantor-safe-eval"

# Defaults — overridable via env at deploy/run time.
MODEL_NAME = os.environ.get("AUMOS_MODAL_MODEL", "facebook/opt-1.3b")
GPU_SPEC = os.environ.get("AUMOS_MODAL_GPU", "A10G")
MAX_TOKENS = int(os.environ.get("AUMOS_MODAL_MAX_TOKENS", "64"))

# The container image: CUDA base + vLLM + the local AumOS safe-eval package.
# We add the local python/safe_eval source so the deployed image runs the real
# AumOS pipeline rather than a vendored copy.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_SAFE_EVAL_SRC = _REPO_ROOT / "python" / "safe_eval"

image = (
    modal.Image.from_registry(
        "nvidia/cuda:12.9.0-devel-ubuntu22.04", add_python="3.12"
    )
    .entrypoint([])  # drop the base image's CMD
    .pip_install("vllm==0.11.0", "torch==2.8.0")
    # Install the local safe_eval package (and its sibling deps if present).
    .add_local_dir(str(_SAFE_EVAL_SRC), "/root/safe_eval")
    .run_commands("pip install -e /root/safe_eval")
)

app = modal.App(APP_NAME, image=image)


# ---------------------------------------------------------------------------
# GPU model server
# ---------------------------------------------------------------------------
@app.cls(gpu=GPU_SPEC, container_idle_timeout=300, timeout=60 * 30)
class VLLMModel:
    """A vLLM-served model running on an A10G GPU.

    The model is loaded once per container in ``setup`` (``@modal.enter()``) so
    repeated calls reuse the warmed engine. ``generate`` exposes a simple
    batched-generation entrypoint used by the safe-eval pipeline.
    """

    model_name: str = MODEL_NAME

    @modal.enter()
    def setup(self) -> None:
        # Imported lazily so the CPU-side image build does not require vLLM.
        from vllm import LLM, SamplingParams  # noqa: F401  (kept for clarity)

        # We construct the SamplingParams inside generate (per-call), but
        # instantiate the engine here so the weights are resident on the GPU.
        self.llm = LLM(model=self.model_name, enforce_eager=False)

    @modal.method()
    def generate(self, prompts: list[str], max_tokens: int = MAX_TOKENS) -> list[str]:
        """Generate completions for a batch of prompts.

        Returns one completion string per prompt, preserving order.
        """
        from vllm import SamplingParams

        params = SamplingParams(max_tokens=max_tokens, temperature=0.0)
        outputs = self.llm.generate(prompts, params)
        # vLLM preserves the input order; each Output has a .outputs[0].text.
        return [o.outputs[0].text for o in outputs]

    @modal.method()
    def health(self) -> dict[str, Any]:
        """Liveness probe."""
        return {"status": "ok", "model": self.model_name, "gpu": GPU_SPEC}


# ---------------------------------------------------------------------------
# safe-eval runner
# ---------------------------------------------------------------------------
@app.function(gpu=GPU_SPEC, timeout=60 * 30)
def run_safe_eval(
    model_name: str = MODEL_NAME,
    prompts: list[str] | None = None,
    max_tokens: int = MAX_TOKENS,
) -> dict[str, Any]:
    """Run the safe-eval pipeline against ``model_name`` on this GPU.

    A default probe prompt set is used when ``prompts`` is ``None``. The
    function:

      * constructs a minimal ``safe_eval.PipelineSpec`` covering the
        ``benchmarks`` stage,
      * registers an inline adapter that reports the generations produced by
        the in-process vLLM engine, and
      * returns the flattened ``PipelineResult`` plus the raw generations.

    Keeping the runner in the same container as the model avoids an HTTP hop and
    lets the benchmark saturate the GPU directly.
    """
    # safe_eval is installed into the image.
    import safe_eval as se  # type: ignore[import-not-found]
    from vllm import LLM, SamplingParams

    if prompts is None:
        prompts = [
            "The capital of France is",
            "Write a short greeting in English.",
            "Explain what an LLM is in one sentence.",
            "Translate 'good morning' to Spanish.",
        ]

    llm = LLM(model=model_name, enforce_eager=False)
    params = SamplingParams(max_tokens=max_tokens, temperature=0.0)
    raw_outputs = llm.generate(prompts, params)
    generations = [o.outputs[0].text for o in raw_outputs]

    # Register an inline benchmarks adapter. The Adapter protocol is
    # ``run(self, target: str, config: dict) -> StageResult``; we close over the
    # generations captured above. The real HELM/LM-Eval adapters slot in here.
    class _InlineBenchmarksAdapter:
        name = "inline"

        def run(self, target: str, config: dict[str, Any]) -> Any:
            metrics = [
                se.Metric(
                    name="prompts_completed",
                    value=float(len(generations)),
                    unit="count",
                ),
                se.Metric(
                    name="mean_generation_chars",
                    value=(
                        sum(len(g) for g in generations) / max(len(generations), 1)
                    ),
                    unit="chars",
                ),
            ]
            return se.StageResult(
                stage_type=se.StageType.BENCHMARKS,
                adapter=self.name,
                metrics=metrics,
                raw_output={"generations": generations},
            )

    se.register_adapter(_InlineBenchmarksAdapter())

    spec = se.PipelineSpec(
        target=model_name,
        stages=[se.StageSpec(type=se.StageType.BENCHMARKS, adapter="inline")],
        metadata={"runner": "modal", "gpu": GPU_SPEC},
    )
    result = se.run_pipeline(spec)

    return {
        "model": model_name,
        "gpu": GPU_SPEC,
        "prompt_count": len(prompts),
        "generations": generations,
        "pipeline": result.to_dict(),
        "veb": se.to_veb(result),
    }


# ---------------------------------------------------------------------------
# Local entrypoint — drives the deployment from the CLI.
# ---------------------------------------------------------------------------
@app.local_entrypoint()
def main(
    model: str = MODEL_NAME,
    max_tokens: int = MAX_TOKENS,
) -> None:
    """Run the safe-eval pipeline and print the results as JSON.

    Usage::

        modal run deploy/modal/safe_eval_modal.py
        modal run deploy/modal/safe_eval_modal.py --model facebook/opt-1.3b
    """
    result = run_safe_eval.remote(model_name=model, max_tokens=max_tokens)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")

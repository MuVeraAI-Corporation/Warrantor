"""Turn a trained adapter into something the benchmark harness can score.

Between :mod:`warrantor_ml.lane_export`, which trains an adapter, and
:mod:`warrantor_ml.benchmark_wildguard`, which scores an Ollama model, there was nothing. The
programme could produce a LoRA adapter and could measure a base model, and no code path joined
them -- so no trained adapter could be compared with the baseline it was trained to beat, which
is the only question the parity gate exists to answer.

The route, established by running it rather than by reading documentation:

1. ``modal volume get`` the adapter directory produced by the lane runner;
2. ``convert_lora_to_gguf.py`` from llama.cpp, against the **local snapshot** of the base;
3. an Ollama ``Modelfile`` whose ``FROM`` is the same GGUF base the baseline was measured on and
   whose ``ADAPTER`` is the converted file;
4. ``ollama create``.

Two things about step 3 that cost time to discover and are therefore asserted here rather than
remembered. **Ollama accepts a GGUF adapter and refuses a safetensors one** against a registry
GGUF base -- and it reports the refusal as ``no Modelfile or safetensors files found`` while
looking directly at an ``adapter_model.safetensors``, so the error names the opposite of the
cause. And **ADAPTER paths resolve relative to the Modelfile's own directory**, so a relative
path that is correct from the shell is wrong once written into the file.

Nothing here trains, downloads a corpus, or contacts a paid API. It shells out to ``modal`` and
``ollama`` and refuses clearly when either is absent.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "PublishPlan",
    "PublishRefused",
    "build_modelfile",
    "candidate_model_name",
    "convert_command",
    "main",
    "plan_publish",
    "publish",
    "write_publish_record",
]


class PublishRefused(RuntimeError):
    """The adapter cannot be turned into a scoreable model, and why."""


#: Files a PEFT adapter directory must carry. The weights alone are not enough: the converter
#: reads rank, alpha and target modules from the config, and silently guessing any of them
#: would produce a GGUF that loads and computes something other than what was trained.
REQUIRED_ADAPTER_FILES = ("adapter_config.json", "adapter_model.safetensors")


@dataclass(frozen=True)
class PublishPlan:
    """Everything the publish needs, resolved and checked before anything runs."""

    adapter_dir: Path
    base_snapshot: Path
    gguf_out: Path
    modelfile: Path
    ollama_base: str
    model_name: str

    def to_dict(self) -> dict[str, str]:
        """Serialisable form, recorded next to the result so a score can be traced to its build."""

        return {
            "adapter_dir": str(self.adapter_dir),
            "base_snapshot": str(self.base_snapshot),
            "gguf_out": str(self.gguf_out),
            "modelfile": str(self.modelfile),
            "ollama_base": self.ollama_base,
            "model_name": self.model_name,
        }


def candidate_model_name(recipe_id: str, run_id: str) -> str:
    """The Ollama tag for one adapter.

    Both the recipe and the run go in the name. A tag carrying only the recipe would be
    overwritten by the next run of the same recipe, and an evaluation already recorded against
    that tag would then describe a model that no longer exists under it.
    """

    return f"warrantor-{recipe_id}-{run_id}".lower()


def build_modelfile(ollama_base: str, gguf_adapter: Path) -> str:
    """Render the Modelfile.

    The adapter path is written absolute on purpose: ``ADAPTER`` resolves relative to the
    directory holding the Modelfile, not the working directory, so a path that is correct when
    typed at a shell silently resolves one level deep once it is written into the file.
    """

    if not gguf_adapter.is_absolute():
        gguf_adapter = gguf_adapter.resolve()
    return f"FROM {ollama_base}\nADAPTER {gguf_adapter.as_posix()}\n"


def _require_tool(name: str, hint: str) -> None:
    if shutil.which(name) is None:
        raise PublishRefused(f"{name} is not on PATH. {hint}")


def plan_publish(
    adapter_dir: Path,
    base_snapshot: Path,
    ollama_base: str,
    recipe_id: str,
    run_id: str,
    workdir: Path,
) -> PublishPlan:
    """Check every precondition and return the plan. Runs nothing.

    Raises:
        PublishRefused: something is missing that would otherwise fail partway through a
            conversion, or -- worse -- produce a model that loads and is not what was trained.
    """

    if not adapter_dir.is_dir():
        raise PublishRefused(f"no adapter directory at {adapter_dir}")

    missing = [name for name in REQUIRED_ADAPTER_FILES if not (adapter_dir / name).is_file()]
    if missing:
        raise PublishRefused(
            f"{adapter_dir} is missing {', '.join(missing)}. A LoRA directory without its "
            "config cannot be converted: rank, alpha and target modules are read from it, and "
            "defaulting any of them yields a GGUF that loads and computes something other than "
            "what was trained."
        )

    if not (base_snapshot / "config.json").is_file():
        raise PublishRefused(
            f"{base_snapshot} does not look like a local model snapshot (no config.json). "
            "convert_lora_to_gguf.py needs a DIRECTORY, not a Hugging Face repo id -- passing "
            "'Qwen/Qwen3Guard-Gen-0.6B' fails with FileNotFoundError on that literal string."
        )

    # Deliberately NOT checking for the ollama binary here. Planning is pure: it reads the
    # filesystem it was given and returns a value, so `--plan-only` works on a machine that
    # will never register anything and the tests need no ambient tooling. The binary is
    # required by `publish`, which checks for it before spending anything on a conversion.

    return PublishPlan(
        adapter_dir=adapter_dir,
        base_snapshot=base_snapshot,
        gguf_out=workdir / f"{run_id}.gguf",
        modelfile=workdir / f"Modelfile.{run_id}",
        ollama_base=ollama_base,
        model_name=candidate_model_name(recipe_id, run_id),
    )


def convert_command(
    plan: PublishPlan, converter: Path, interpreter: str | None = None
) -> list[str]:
    """The llama.cpp conversion command, as a list. Returned rather than run, so it is testable.

    ``--outtype f16`` and not a quantised type: the adapter is quantised implicitly by the base
    it is applied to, and quantising the delta separately would compound two roundings that the
    baseline's Q4_K_M measurement never saw.

    ``interpreter`` defaults to ``sys.executable`` rather than the string ``"python"``. The
    converter needs torch, safetensors and gguf, and ``"python"`` resolves to whatever is first
    on PATH -- which on a machine where the training environment is a separate venv (or in WSL,
    while this runs on Windows) is a different interpreter from the one running this code, and
    the failure is an ImportError several seconds into a conversion rather than a refusal.
    """

    return [
        interpreter or sys.executable,
        str(converter),
        "--base",
        str(plan.base_snapshot),
        "--outtype",
        "f16",
        "--outfile",
        str(plan.gguf_out),
        str(plan.adapter_dir),
    ]


def publish(
    plan: PublishPlan,
    converter: Path | None = None,
    interpreter: str | None = None,
    prebuilt_gguf: Path | None = None,
) -> dict[str, str]:
    """Convert and register. Returns the plan plus what was produced.

    ``prebuilt_gguf`` skips the conversion and registers an adapter converted elsewhere. That is
    not a convenience: the converter needs torch in a CUDA-capable environment while Ollama runs
    wherever the GPU is exposed to it, and on a Windows box with a WSL training venv those are
    two filesystems with two path forms that cannot be handed to one subprocess. Splitting the
    phases is the honest fit rather than pretending one interpreter can reach both.
    """

    # Order matters. The caller's own mistakes are named first, because "you passed neither
    # --converter nor --gguf" is actionable anywhere, while "ollama is not on PATH" is a fact
    # about this machine that would otherwise mask it. Then the environment, and only then any
    # work -- a missing Ollama found after the GGUF is written is a refusal that cost minutes.
    if prebuilt_gguf is None and converter is None:
        raise PublishRefused(
            "one of --converter or --gguf is required: either convert the adapter here, or "
            "name one converted elsewhere. Neither is assumed, because registering without "
            "an adapter yields a model tag that scores as the untuned base."
        )
    if prebuilt_gguf is not None and not prebuilt_gguf.is_file():
        raise PublishRefused(f"no GGUF adapter at {prebuilt_gguf}")

    _require_tool("ollama", "Install Ollama; the baseline was measured through it.")

    plan.gguf_out.parent.mkdir(parents=True, exist_ok=True)

    if prebuilt_gguf is not None:
        if prebuilt_gguf.resolve() != plan.gguf_out.resolve():
            shutil.copyfile(prebuilt_gguf, plan.gguf_out)
    else:
        completed = subprocess.run(  # fixed argv, never a shell string
            convert_command(plan, converter, interpreter),
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise PublishRefused(
                f"convert_lora_to_gguf.py failed ({completed.returncode}):"
                f"\n{completed.stderr[-2000:]}"
            )

    if not plan.gguf_out.is_file():
        raise PublishRefused(
            f"the converter reported success and wrote no file at {plan.gguf_out}. "
            "Registering an absent adapter would produce a model tag that scores as the "
            "untuned base and reads as the candidate."
        )

    plan.modelfile.write_text(build_modelfile(plan.ollama_base, plan.gguf_out), encoding="utf-8")
    created = subprocess.run(  # fixed argv, never a shell string
        ["ollama", "create", plan.model_name, "-f", str(plan.modelfile)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        raise PublishRefused(
            f"ollama create failed ({created.returncode}):\n{created.stderr[-2000:]}\n\n"
            "If this says 'no Modelfile or safetensors files found', the ADAPTER is pointing at "
            "a safetensors directory. Ollama takes a GGUF adapter against a GGUF base; the "
            "message names the opposite of the cause."
        )

    record = plan.to_dict()
    record["gguf_bytes"] = str(plan.gguf_out.stat().st_size)
    return record


def write_publish_record(record: dict[str, str], destination: Path) -> None:
    """Persist what was built, so a benchmark result can be traced back to the adapter behind it."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    """CLI for ``warrantor-ml-publish``."""

    parser = argparse.ArgumentParser(
        prog="warrantor-ml-publish",
        description="Convert a trained LoRA adapter to GGUF and register it with Ollama, so "
        "the benchmark harness can score it on the baseline's lane and precision.",
    )
    parser.add_argument("--adapter", type=Path, required=True, help="the PEFT adapter directory")
    parser.add_argument(
        "--base-snapshot",
        type=Path,
        required=True,
        help="LOCAL directory of the base model (a HF cache snapshot). Not a repo id: "
        "convert_lora_to_gguf.py fails on the literal string",
    )
    parser.add_argument(
        "--ollama-base",
        required=True,
        help="the Ollama tag the BASELINE was measured on. Anything else makes the comparison "
        "cross-precision and the parity gate refuses it",
    )
    parser.add_argument("--recipe-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--workdir", type=Path, default=Path("adapters"))
    parser.add_argument(
        "--converter",
        type=Path,
        help="path to llama.cpp's convert_lora_to_gguf.py (pure Python; no C++ build needed). "
        "One of --converter or --gguf is required",
    )
    parser.add_argument(
        "--gguf",
        type=Path,
        help="an already-converted GGUF adapter, skipping the conversion. Use this when the "
        "converter and Ollama live in different environments -- a WSL training venv and a "
        "Windows Ollama cannot be handed to one subprocess",
    )
    parser.add_argument(
        "--python",
        help="interpreter to run the converter with (default: the one running this). The "
        "converter needs torch, safetensors and gguf; if those live in a different venv or in "
        "WSL, name it here rather than discovering an ImportError mid-conversion",
    )
    parser.add_argument("--record-out", type=Path, help="write the publish record here")
    parser.add_argument(
        "--plan-only", action="store_true", help="check preconditions and exit, converting nothing"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``warrantor-ml-publish``."""

    arguments = build_parser().parse_args(argv)
    try:
        plan = plan_publish(
            arguments.adapter,
            arguments.base_snapshot,
            arguments.ollama_base,
            arguments.recipe_id,
            arguments.run_id,
            arguments.workdir,
        )
    except PublishRefused as refusal:
        print(f"\nNOT PUBLISHED\n{refusal}")
        return 2

    if arguments.plan_only:
        print(json.dumps(plan.to_dict(), indent=2))
        print("\nPLAN ONLY -- nothing was converted and no model was registered.")
        return 0

    try:
        record = publish(plan, arguments.converter, arguments.python, arguments.gguf)
    except PublishRefused as refusal:
        print(f"\nNOT PUBLISHED\n{refusal}")
        return 2

    print(json.dumps(record, indent=2))
    if arguments.record_out is not None:
        write_publish_record(record, arguments.record_out)
        print(f"publish record: {arguments.record_out}")
    print(
        f"\nScore it with:\n  python ml/benchmark_wildguard.py --backend ollama "
        f"--model {plan.model_name} --seed 0 --num-ctx 8192 --out results/{plan.model_name}.json"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

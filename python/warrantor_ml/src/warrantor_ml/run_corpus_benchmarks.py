#!/usr/bin/env python3
"""One command for the two gated-corpus benchmarks: `python ml/run_corpus_benchmarks.py`.

# Why this lives here and not in `ml/`

It was written into `ml/` at 186 lines, beside launchers of 28. `ml/README.md` forbids exactly
that in its own words: the CI gate globs `python/*/pyproject.toml`, so nothing under `ml/` is
linted, format-checked or tested, and putting logic there creates "an ungoverned code surface
inside a governance substrate". CI could not catch it either -- the file was invisible to the
very check that would have flagged it. Only reading the README that sat next to it did.

# Why this exists

`docs/W1-delivery-gaps.md` §4.1c is blocked on a credential rather than on compute. Both primary
corpora sit behind Hugging Face click-through terms, so the sequence is: accept two forms, export
one token, run two scripts with matching flags. That is four steps in which the only interesting
failure -- running the two benchmarks at *different* sampling settings and comparing the results --
is silent.

So this pins the knobs in one place, checks the preconditions **before** touching a model, and
refuses with a sentence naming what is missing rather than a stack trace from inside `datasets`.

# What it deliberately does not do

It does not accept the licences for you, and it cannot: they are click-through agreements bound to
an account. It does not read a token from anywhere but the environment. And it does not invent a
default output path -- results carry a date because a results file whose provenance is "the last
time somebody ran it" is a file nobody can compare against anything.

# The number this is chasing, and why it is not urgent

The reason those figures mattered was the possibility that the shipped configuration was not the
measured one -- which was true once: this crate ran `num_ctx: 4096` for eight releases while every
published figure was measured at 8192. That is closed twice over now, by `tests/guard_parity.rs`
reading the Python evaluator's own source, and by `warrantor guard bench` measuring the *running*
configuration on any machine. This re-derives figures we already have reason to believe apply.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

# python/warrantor_ml/src/warrantor_ml/run_corpus_benchmarks.py -> repository root is five up.
# Asserted below rather than trusted: a wrong hop count still produces a valid Path, and the
# failure would be "the benchmark scripts are missing" pointing at a directory that never existed.
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
ML_DIRECTORY = REPOSITORY_ROOT / "ml"

# The sampling settings every published figure was measured at. One place, passed to both, because
# two benchmarks run at different settings produce two numbers that cannot be compared and nothing
# says so.
NUM_CTX = 8192
SEED = 0

BENCHMARKS = (
    (
        "wildguard",
        "benchmark_wildguard.py",
        "WildGuardTest -- 47% adversarial, the recall figure",
    ),
    (
        "expguard",
        "benchmark_expguard.py",
        "ExpGuardTest -- the false-positive-rate figure",
    ),
)

GATES = (
    "https://huggingface.co/datasets/allenai/wildguardmix",
    "https://huggingface.co/datasets/Qwen/ExpGuardMix",
)


def preflight(endpoint: str) -> list[str]:
    """Everything that must be true before a single model call, as a list of complaints.

    Checked up front and reported together. Discovering the token is missing *after* the first
    corpus has downloaded is the shape of failure this function exists to prevent.
    """
    problems: list[str] = []

    if not (os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")):
        problems.append(
            "HF_TOKEN is not set. Both corpora are gated: accept the terms at\n"
            + "".join(f"    {url}\n" for url in GATES)
            + "  then `export HF_TOKEN=hf_...`. The gates are auto-approved on submit -- no human\n"
            "  reviews them -- but they still require a logged-in account and an accepted form."
        )

    try:
        import pyarrow  # noqa: F401
    except ImportError:
        problems.append(
            "pyarrow is not importable, and the corpora are parquet. Install the extras:\n"
            "    pip install -e python/warrantor_ml[parquet,hub]"
        )

    for _, script, _ in BENCHMARKS:
        if not (ML_DIRECTORY / script).exists():
            problems.append(
                f"{ML_DIRECTORY / script} is missing. This module resolves the repository root\n"
                "  by parent count; if the file was moved, that count is now wrong."
            )

    if shutil.which("ollama") is None:
        # A warning rather than a refusal: the endpoint may be a remote ollama-compatible server,
        # and refusing on the absence of a local binary would be a guess about somebody's setup.
        problems.append(
            f"NOTE (not fatal): no `ollama` on PATH. The benchmarks will call {endpoint} anyway;\n"
            "  if that is a remote endpoint this is fine, and if it is not, they will fail there."
        )

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=REPOSITORY_ROOT / "eval_results",
        help="where the two JSON result documents go (default: ./eval_results)",
    )
    parser.add_argument("--model", help="ollama model tag; defaults to each benchmark's own")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434")
    parser.add_argument(
        "--check",
        action="store_true",
        help="run the preconditions and exit, calling no model and downloading nothing",
    )
    args = parser.parse_args()

    problems = preflight(args.endpoint)
    fatal = [p for p in problems if not p.startswith("NOTE")]
    for problem in problems:
        print(f"  {problem}\n", file=sys.stderr)

    if fatal:
        print(
            f"{len(fatal)} precondition(s) unmet; nothing was run and nothing was downloaded.",
            file=sys.stderr,
        )
        return 1
    if args.check:
        print("preconditions met. Re-run without --check to measure.")
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = date.today().isoformat()
    failures = 0

    for name, script, what in BENCHMARKS:
        out = args.out_dir / f"{name}-{stamp}.json"
        command = [
            sys.executable,
            str(ML_DIRECTORY / script),
            "--endpoint",
            args.endpoint,
            "--num-ctx",
            str(NUM_CTX),
            "--seed",
            str(SEED),
            "--out",
            str(out),
        ]
        if args.model:
            command += ["--model", args.model]

        print(f"\n=== {name}: {what}")
        print(f"    {' '.join(command)}")
        result = subprocess.run(command, check=False)
        if result.returncode != 0:
            failures += 1
            # Not aborted. The second benchmark measures a different property, and a WildGuardTest
            # failure says nothing about whether ExpGuardTest can run.
            print(
                f"    {name} exited {result.returncode}; continuing to the next.",
                file=sys.stderr,
            )
        else:
            print(f"    wrote {out}")

    print(
        f"\nBoth benchmarks ran at num_ctx={NUM_CTX}, seed={SEED} -- the settings every published\n"
        "figure was measured at. Compare against 0.8152 adversarial recall (WildGuardTest) and\n"
        "0.0923 adversarial false-positive rate (ExpGuardTest). A difference is a finding about\n"
        "THIS configuration, not about the model in general."
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

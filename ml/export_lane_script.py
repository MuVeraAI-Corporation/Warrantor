#!/usr/bin/env python3
"""CLI entry point for ``warrantor_ml.programme:export_main``.

Renders the standalone Kaggle or Modal runner for a recipe. It writes a file and runs nothing:
dispatching the job is the orchestrator's decision.

The scripts are GENERATED rather than hand-written because nothing under ``ml/`` is discovered
by ``tools/ci/run_python_checks.py`` -- no ruff, no pytest. Generated output from a gated
generator is how this repository ships code the gate cannot otherwise see.

Run: ``python ml/export_lane_script.py --help``
"""

from __future__ import annotations

import sys

from _bootstrap import ensure_importable

ensure_importable()

from warrantor_ml.programme import export_main  # noqa: E402

if __name__ == "__main__":
    sys.exit(export_main())

#!/usr/bin/env python3
"""CLI entry point for ``warrantor_ml.evaluate``.

The implementation lives at ``python/warrantor_ml/src/warrantor_ml/evaluate.py``, inside the
repository's Python CI gate (ruff lint, ruff format, pytest). This file is a thin, deliberate
shim.

Why the split: ``tools/ci/run_python_checks.py`` discovers projects by globbing
``python/*/pyproject.toml``. A directory at ``ml/`` is not under ``python/`` at all, so it is
never discovered -- no lint, no format check, no tests. Training and evaluation code also never
executes in CI, so under ``ml/`` it would be entirely unverified: an ungoverned code surface
inside a governance substrate, which is precisely the SG1 anti-pattern. So the logic lives
where the gate can see it, and ``ml/`` stays a launcher.

Running ``python ml/evaluate.py`` puts this directory on ``sys.path`` automatically, which is
what makes the ``_bootstrap`` import below resolve in a bare checkout.

Run: ``python ml/evaluate.py --help``
"""

from __future__ import annotations

import sys

from _bootstrap import ensure_importable

ensure_importable()

from warrantor_ml.evaluate import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

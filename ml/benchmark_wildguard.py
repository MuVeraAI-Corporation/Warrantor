#!/usr/bin/env python3
"""CLI entry point for ``warrantor_ml.benchmark_wildguard``.

The implementation lives at
``python/warrantor_ml/src/warrantor_ml/benchmark_wildguard.py``, inside the repository's Python
CI gate (ruff lint, ruff format, pytest). This file is a thin, deliberate shim -- see
``ml/README.md`` for why the split exists.

This is the evaluation that decides whether a guard candidate is real. ``ml/evaluate.py`` runs
any labelled JSONL set, including the hand-written smoke set that a purpose-built guard will
ace; this one runs the held-out, human-annotated WildGuardTest split, 47% of which is
adversarial. Reach for this before believing any recall number.

Requires ``pyarrow`` (``pip install -e python/warrantor_ml[parquet,hub]``) and an accepted
WildGuardMix gate on the Hub.

Run: ``python ml/benchmark_wildguard.py --help``
"""

from __future__ import annotations

import sys

from _bootstrap import ensure_importable

ensure_importable()

from warrantor_ml.benchmark_wildguard import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

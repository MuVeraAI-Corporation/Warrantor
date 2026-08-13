#!/usr/bin/env python3
"""CLI entry point for ``warrantor_ml.benchmark_expguard``.

The implementation lives at
``python/warrantor_ml/src/warrantor_ml/benchmark_expguard.py``, inside the repository's Python
CI gate (ruff lint, ruff format, pytest). This file is a thin, deliberate shim -- see
``ml/README.md`` for why the split exists.

``ml/benchmark_wildguard.py`` answers "is this guard real on a general adversarial corpus".
This one answers the vertical-pack question: **does a general-purpose guard degrade on
specialised professional content, and in which domain?** ExpGuardTest's ``domain`` column splits
into ``finance`` / ``healthcare`` / ``law``, and the per-domain recall -- not the aggregate --
is what decides whether each pack needs its own tuned model.

Start with ``--describe-only``. It prints the real schema and label vocabulary without touching
the model, which is the only way to notice that the corpus has no general band and spells the
legal vertical ``law``.

Requires ``pyarrow`` (``pip install -e python/warrantor_ml[parquet,hub]``) and an accepted
ExpGuardMix gate on the Hub.

Run: ``python ml/benchmark_expguard.py --help``
"""

from __future__ import annotations

import sys

from _bootstrap import ensure_importable

ensure_importable()

from warrantor_ml.benchmark_expguard import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""CLI entry point for ``warrantor_ml.programme:parity_main``.

The blind parity gate. Reads a result document produced by ``ml/benchmark_wildguard.py`` or
``ml/benchmark_expguard.py`` and returns one of three verdicts: ``promote``, ``reject`` or
``insufficient_evidence``.

Exit codes are 0 / 1 / 3 respectively. The third is deliberately not 1 -- "we could not tell"
and "it did not work" call for different next actions, and a job that treats them the same
retries the wrong one.

Run: ``python ml/parity.py --help``
"""

from __future__ import annotations

import sys

from _bootstrap import ensure_importable

ensure_importable()

from warrantor_ml.programme import parity_main  # noqa: E402

if __name__ == "__main__":
    sys.exit(parity_main())

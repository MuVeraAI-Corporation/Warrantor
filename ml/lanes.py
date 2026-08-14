#!/usr/bin/env python3
"""CLI entry point for ``warrantor_ml.programme:lanes_main``.

Resolves a recipe against a compute lane and REFUSES a configuration that will not fit in the
lane's VRAM or finish inside its session cap. Pure arithmetic -- no GPU is touched and nothing
is downloaded, so the routing question is answerable before a run is started rather than at hour
eleven of a twelve-hour Kaggle session.

Run: ``python ml/lanes.py --help``
"""

from __future__ import annotations

import sys

from _bootstrap import ensure_importable

ensure_importable()

from warrantor_ml.programme import lanes_main  # noqa: E402

if __name__ == "__main__":
    sys.exit(lanes_main())

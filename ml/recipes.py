#!/usr/bin/env python3
"""CLI entry point for ``warrantor_ml.programme:recipes_main``.

Prints the eight training recipes with their stable digests. A recipe digest is what makes a
Kaggle run and a Modal run of "the same recipe" provably the same recipe rather than two scripts
edited in parallel.

Run: ``python ml/recipes.py --help``
"""

from __future__ import annotations

import sys

from _bootstrap import ensure_importable

ensure_importable()

from warrantor_ml.programme import recipes_main  # noqa: E402

if __name__ == "__main__":
    sys.exit(recipes_main())

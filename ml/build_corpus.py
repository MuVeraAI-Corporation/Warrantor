#!/usr/bin/env python3
"""CLI entry point for ``warrantor_ml.build_corpus``.

The implementation lives at ``python/warrantor_ml/src/warrantor_ml/build_corpus.py``, inside
the repository's Python CI gate (ruff lint, ruff format, pytest). This file is a thin,
deliberate shim -- see ``ml/README.md`` for why the split exists.

Start with ``--describe-only``. It prints the split's real schema and label vocabulary without
selecting or writing anything, which is the only way to notice that a train split spells a harm
category differently from the test split the weak-category targets were measured on. A selector
written against the wrong spelling selects nothing, and nothing looks exactly like a corpus that
has no such rows.

Run: ``python ml/build_corpus.py --help``
"""

from __future__ import annotations

import sys

from _bootstrap import ensure_importable

ensure_importable()

from warrantor_ml.build_corpus import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

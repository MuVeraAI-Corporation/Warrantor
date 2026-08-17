#!/usr/bin/env python3
"""CLI entry point for ``warrantor_ml.run_corpus_benchmarks``.

The implementation lives at
``python/warrantor_ml/src/warrantor_ml/run_corpus_benchmarks.py``, inside the repository's Python
CI gate (ruff lint, ruff format, pytest). This file is a thin, deliberate shim -- see
``ml/README.md`` for why the split exists.

Runs both gated-corpus benchmarks at one pinned configuration. Start with ``--check``: it verifies
every precondition -- the Hugging Face token, the parquet reader, the scripts themselves -- without
calling a model or downloading a corpus, and names what is missing rather than failing with an
HTTP 401 from inside a dataset loader.

Run: ``python ml/run_corpus_benchmarks.py --help``
"""

from __future__ import annotations

import sys

from _bootstrap import ensure_importable

ensure_importable()

from warrantor_ml.run_corpus_benchmarks import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

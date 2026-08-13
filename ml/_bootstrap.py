"""Make ``warrantor_ml`` importable when running these scripts from a bare checkout.

The implementation lives at ``python/warrantor_ml/src/warrantor_ml``. Installing it
(``pip install -e python/warrantor_ml``) is the supported path; this shim exists so
``python ml/evaluate.py --help`` works in a fresh clone without one.
"""

from __future__ import annotations

import sys
from pathlib import Path

__all__ = ["ensure_importable"]


def ensure_importable() -> Path:
    """Put the package's ``src`` directory on ``sys.path`` and return it."""

    source_root = Path(__file__).resolve().parents[1] / "python" / "warrantor_ml" / "src"
    if source_root.is_dir():
        candidate = str(source_root)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    return source_root

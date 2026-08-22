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
    """Put the package's ``src`` directory on ``sys.path`` and return it.

    Also removes this directory (``ml/``, the launcher's own) from ``sys.path``. Python puts the
    invoking script's directory at ``sys.path[0]``, and this directory contains ``datasets.py`` —
    the launcher for the dataset registry. With the directory on the path, any later
    ``import datasets`` in the training stack resolved to THAT file instead of Hugging Face's
    ``datasets`` package, and every local training run died with ``cannot import name
    'load_dataset'`` before touching the GPU. Found the first time the local lane was ever run;
    the Modal lane never saw it because its exported scripts live in their own directory.

    Safe for the launchers themselves: each does ``from _bootstrap import ensure_importable``
    first, so this module is already in ``sys.modules`` by the time the strip happens, and no
    launcher imports another ``ml/`` file by module name.
    """

    here = str(Path(__file__).resolve().parent)
    while here in sys.path:
        sys.path.remove(here)

    source_root = Path(__file__).resolve().parents[1] / "python" / "warrantor_ml" / "src"
    if source_root.is_dir():
        candidate = str(source_root)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    return source_root

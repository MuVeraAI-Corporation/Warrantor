#!/usr/bin/env python3
"""CLI entry point for ``warrantor_ml.publish:main``.

Converts a trained LoRA adapter to GGUF and registers it with Ollama, which is the only way a
candidate reaches the lane and precision the baseline was measured on. Between training and
scoring there was previously nothing at all.

Run: ``python ml/publish_adapter.py --help``
"""

from __future__ import annotations

import sys

from _bootstrap import ensure_importable

ensure_importable()

from warrantor_ml.publish import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())

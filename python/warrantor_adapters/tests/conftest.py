"""Conftest: ensure the warrantor SDK is importable for adapter tests."""

import os
import sys

_SDK_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "warrantor", "src")
if os.path.isdir(_SDK_SRC) and _SDK_SRC not in sys.path:
    sys.path.insert(0, _SDK_SRC)

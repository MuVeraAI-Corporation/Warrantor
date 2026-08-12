"""CI test: every cookbook recipe runs without error.

A broken recipe is a release blocker. This test imports and runs each recipe's main() function.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

EXAMPLES_DIR = Path(__file__).parent

# Ensure the warrantor SDK is importable.
_ROOT = EXAMPLES_DIR.parent
for _pkg in ("warrantor", "warrantor_adapters"):
    _src = _ROOT / "python" / _pkg / "src"
    if _src.is_dir() and str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

RECIPES = [
    "01_first_receipt",
    "02_langchain_agent",
    "03_spend_cap",
    "04_human_approval",
    "05_rag_agent",
    "06_computer_use",
]


@pytest.mark.parametrize("recipe", RECIPES)
def test_recipe_runs(recipe: str) -> None:
    """Each recipe's main() must run without raising."""
    # Import the recipe module from the examples directory.
    spec = importlib.util.spec_from_file_location(recipe, EXAMPLES_DIR / f"{recipe}.py")
    assert spec is not None and spec.loader is not None, f"cannot load {recipe}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[recipe] = mod  # required for @dataclass and other introspection
    spec.loader.exec_module(mod)
    # Run main() — it must not raise.
    mod.main()

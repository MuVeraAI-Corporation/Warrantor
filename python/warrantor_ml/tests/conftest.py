"""Make these tests import the package they sit beside, not whichever copy is installed.

# Why this file exists

`warrantor_ml` is installed editable, and on this machine that install pointed at a DIFFERENT
git worktree. So `python -m pytest` collected the test files from this tree while importing the
module from the other one, and reported passes for code that was never executed -- including a
regression test for a fix that only existed here. A green suite testing someone else's checkout
is worse than a red one, because it is indistinguishable from having verified the change.

Prepending the sibling `src` makes the import follow the checkout rather than the environment.
Concurrent worktrees are normal in this repository, so this is a standing hazard, not a one-off.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

"""Shared helper for the per-paper revision scripts.

Every edit is an exact-substring replacement that must match EXACTLY ONCE. A pattern that matches
zero times is a silent no-op -- the defect ships -- and one that matches twice edits something it
was never meant to touch. Both are reported, neither is tolerated, and the file is written only if
every edit in the list landed. A partially-revised paper is worse than an unrevised one, because it
looks finished.
"""
from __future__ import annotations

import io
import os
import sys

DRAFTS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                      "drafts")


def revise(filename: str, edits: list[tuple[str, str]]) -> int:
    path = os.path.join(DRAFTS, filename)
    text = io.open(path, encoding="utf-8").read()
    problems = []
    for i, (old, new) in enumerate(edits, 1):
        n = text.count(old)
        if n != 1:
            problems.append(f"  edit {i}: matched {n} times (need exactly 1): {old[:70]!r}")
            continue
        text = text.replace(old, new)
    if problems:
        print(f"{filename}: NOT WRITTEN -- {len(problems)} edit(s) did not land")
        print("\n".join(problems))
        return 1
    io.open(path, "w", encoding="utf-8", newline="\n").write(text)
    print(f"{filename}: {len(edits)} edits applied")
    return 0


def main(filename: str, edits: list[tuple[str, str]]) -> None:
    sys.exit(revise(filename, edits))

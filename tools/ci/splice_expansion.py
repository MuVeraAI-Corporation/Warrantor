#!/usr/bin/env python3
"""Splice an expanded task section into the implementation plan.

The plan is one file and expansions are written concurrently by separate agents, so splicing is
serial and here rather than in the agents. This script is the only writer.

A section runs from its own `### Task N.M:` heading to the next `### Task ` or `## Phase` heading.
Refuses the splice unless the replacement is actually an expansion: it must declare its own branch
(the status board reads each task's branch from a `worktree add -b` line), carry numbered steps, and
not shrink the section.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from task_status import declared_branch  # noqa: E402  the single reader of the branch line

PLAN = Path("docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md")
SECTION_START = re.compile(r"^### Task (\d+\.\d+):")
SECTION_END = re.compile(r"^(### Task |## Phase )")
STEP_LINE = re.compile(r"^- \[ \] \*\*Step \d+", re.MULTILINE)
FENCE = re.compile(r"^```", re.MULTILINE)


def find_section(lines: list[str], task_id: str) -> tuple[int, int]:
    """Return [start, end) line indices of the task's section, or raise."""
    start = None
    for i, line in enumerate(lines):
        m = SECTION_START.match(line)
        if m and m.group(1) == task_id:
            start = i
            break
    if start is None:
        raise SystemExit(f"FAIL: no `### Task {task_id}:` heading in {PLAN}")
    for j in range(start + 1, len(lines)):
        if SECTION_END.match(lines[j]):
            return start, j
    return start, len(lines)


def measure(text: str) -> dict[str, int]:
    return {
        "steps": len(STEP_LINE.findall(text)),
        "blocks": len(FENCE.findall(text)) // 2,
        "words": len(text.split()),
        "lines": text.count("\n"),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("task_id")
    ap.add_argument("expansion", type=Path)
    # Thresholds are measured, not guessed. Fully expanded Phase 0-2 tasks average 9-11 steps,
    # 16-22 code blocks and 4,100-8,000 words. The structural Phase 3-14 seeds already average
    # 6-8 steps but ~0 code blocks and ~400 words -- so step COUNT does not separate an
    # expansion from a seed, and a floor of 6 would pass every seed unchanged. Code blocks and
    # word count are what actually move, and steps must not go backward.
    ap.add_argument("--min-steps", type=int, default=8)
    ap.add_argument("--min-blocks", type=int, default=8)
    ap.add_argument("--min-words", type=int, default=2500)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not PLAN.exists():
        raise SystemExit(f"FAIL: run from the repository root; {PLAN} not found")
    new = args.expansion.read_text(encoding="utf-8").rstrip() + "\n\n"

    head = new.splitlines()[0] if new.strip() else ""
    m = SECTION_START.match(head)
    if not m:
        raise SystemExit(f"FAIL: expansion must start with `### Task {args.task_id}:`, got {head!r}")
    if m.group(1) != args.task_id:
        raise SystemExit(f"FAIL: expansion declares Task {m.group(1)}, spliced as {args.task_id}")

    after = measure(new)
    problems = []
    if after["steps"] < args.min_steps:
        problems.append(f"{after['steps']} numbered steps, need >= {args.min_steps}")
    if after["blocks"] < args.min_blocks:
        problems.append(f"{after['blocks']} code blocks, need >= {args.min_blocks}; a task with no "
                        "verbatim test bodies or captured output is still structural")
    if after["words"] < args.min_words:
        problems.append(f"{after['words']} words, need >= {args.min_words}")
    # Resolved by the board's own reader, so a branch this gate accepts is a branch the board
    # will find. It returns '' both for a missing line and for a `<template>` left in prose.
    branch = declared_branch(new)
    if not branch:
        problems.append("no `worktree add ... -b <branch>` line naming a real branch; the status "
                        "board would resolve this task to an invented branch name")

    lines = PLAN.read_text(encoding="utf-8").splitlines(keepends=True)
    start, end = find_section(lines, args.task_id)
    old = "".join(lines[start:end])
    before = measure(old)

    # No regression on any axis. Gate messages stay ASCII: they are read in CI logs and through
    # grep, and a non-ASCII dash made one of these look like binary output.
    for axis in ("words", "steps", "blocks"):
        if after[axis] < before[axis]:
            problems.append(f"replacement has fewer {axis} than the seed "
                            f"({after[axis]} vs {before[axis]}) - that is a regression")

    print(f"Task {args.task_id}: plan lines {start + 1}..{end}")
    for k in ("steps", "blocks", "words"):
        print(f"  {k:7} {before[k]:>6} -> {after[k]:>6}")
    if branch:
        print(f"  branch  {branch}")

    if problems:
        for p in problems:
            print(f"FAIL: {p}", file=sys.stderr)
        return 1
    if args.dry_run:
        print("dry run: not written")
        return 0

    PLAN.write_text("".join(lines[:start]) + new + "".join(lines[end:]), encoding="utf-8")
    print(f"spliced into {PLAN}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

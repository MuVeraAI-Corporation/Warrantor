#!/usr/bin/env python3
"""Assert the Phases 7-14 scope document accounts for every uncovered catalog item, once.

The scope document exists because the implementation plan silently covered only 57 of the
master blueprint's 189 catalog items, and nobody noticed until the codes were counted. A
scope document that drops an item the same way would reproduce the defect it was written to
fix, so the accounting is a machine check rather than a reading.

Three sources, and the checker never trusts the scope document about any of them:

  catalog    every `<article class="item" id="Lx-nn">` in the master blueprint
  covered    every L-code appearing anywhere in the implementation plan
  scoped     the *Items* column of each task row in the scope document, and nothing else

Only the Items column counts. Anchor prose legitimately cross-references a code owned by
another task -- Task 7.4's anchor names the L4-25 deny floor that Task 7.1 builds -- and
counting those would report a duplicate for a document that is correct.
"""

from __future__ import annotations

import contextlib
import re
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MASTER = REPOSITORY_ROOT / "docs/html/warrantor-native-ai-platform-os-master-2026-09-01.html"
PLAN = REPOSITORY_ROOT / "docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md"
SCOPE = REPOSITORY_ROOT / "docs/superpowers/plans/2026-09-05-phases-7-14-scope.md"

LCODE = re.compile(r"\bL(?:1[01]|[0-9])-\d{2}\b")
CATALOG_ITEM = re.compile(r'<article class="item" id="(L(?:1[01]|[0-9])-\d{2})"')
TASK_ROW = re.compile(r"^\|\s*\*\*(\d+\.\d+)\*\*")


def read(path: Path) -> str:
    if not path.exists():
        sys.exit(f"::error::missing input: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def catalog_items() -> set[str]:
    return set(CATALOG_ITEM.findall(read(MASTER)))


def plan_covered() -> set[str]:
    return set(LCODE.findall(read(PLAN)))


def scoped_items() -> tuple[dict[str, list[str]], list[str]]:
    """Map task id -> its Items column codes, in document order.

    Returns the map and the flat list, so a duplicate can be reported with both owners.
    """
    per_task: dict[str, list[str]] = {}
    flat: list[str] = []
    for line in read(SCOPE).splitlines():
        m = TASK_ROW.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        codes = LCODE.findall(cells[1])
        per_task[m.group(1)] = codes
        flat.extend(codes)
    return per_task, flat


def main() -> int:
    # Windows consoles default to a code page that cannot encode the box-drawing and dash
    # characters this repository's prose uses. Reconfigure the stream rather than requiring
    # PYTHONIOENCODING, which makes the tool fail only on the one platform CI never runs.
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")

    catalog = catalog_items()
    uncovered = catalog - plan_covered()
    per_task, flat = scoped_items()

    findings: list[str] = []

    owners: dict[str, list[str]] = {}
    for task, codes in per_task.items():
        for c in codes:
            owners.setdefault(c, []).append(task)

    for code, tasks in sorted(owners.items()):
        if len(tasks) > 1:
            findings.append(f"{code} is claimed by more than one task: {', '.join(tasks)}")

    for code in sorted(uncovered - set(flat)):
        findings.append(f"{code} is uncovered by the plan and scoped by no task")

    for code in sorted(set(flat) - uncovered):
        where = ", ".join(owners[code])
        reason = "not in the catalog" if code not in catalog else "already covered by the plan"
        findings.append(f"{code} is scoped by task {where} but is {reason}")

    for task, codes in sorted(per_task.items()):
        if not codes:
            findings.append(f"task {task} has an empty Items column")

    print(
        f"phase scope: {len(per_task)} tasks account for {len(set(flat))} of "
        f"{len(uncovered)} uncovered items, out of a catalog of {len(catalog)}"
    )
    if findings:
        for f in findings:
            print(f"::error::phase scope: {f}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

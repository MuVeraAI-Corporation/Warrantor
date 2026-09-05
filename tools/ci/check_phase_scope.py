#!/usr/bin/env python3
"""Assert the Phases 7-14 scope document accounts for every uncovered catalog item, once.

The scope document exists because the implementation plan silently covered only 57 of the
master blueprint's 189 catalog items, and nobody noticed until the codes were counted. A
scope document that drops an item the same way would reproduce the defect it was written to
fix, so the accounting is a machine check rather than a reading.

Three sources, and the checker never trusts the scope document about any of them:

  catalog    every `<article class="item" id="Lx-nn">` in the master blueprint
  covered    L-codes in the implementation plan ABOVE its `## Phase 7` heading, because
             below that heading the plan is this scope document being fulfilled
  scoped     the *Items* column of each task row in the scope document, and nothing else
  seeded     the L-codes in each `### Task N.M:` heading below `## Phase 7`

Only the Items column counts for `scoped`. Anchor prose legitimately cross-references a code
owned by another task -- Task 7.4's anchor names the L4-25 deny floor that Task 7.1 builds --
and counting those would report a duplicate for a document that is correct.

`seeded` exists to catch drift the other direction: a task seeded into the plan with different
items than its scope row silently rescopes the work, and the plan is what a lane executes.
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
ROUTE_SUMMARY_ROW = re.compile(r"^\|\s*`([a-z0-9.\-]+)`\s*\|\s*(\d+)\s*\|")


def read(path: Path) -> str:
    if not path.exists():
        sys.exit(f"::error::missing input: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def catalog_items() -> set[str]:
    return set(CATALOG_ITEM.findall(read(MASTER)))


def plan_covered() -> set[str]:
    """L-codes covered by the ORIGINAL plan — Phases 0 through 6 only.

    Seeding a scoped task into the plan puts its L-codes into the plan file, which is the
    scope document being fulfilled rather than a conflict with it. Counting the whole file
    made the checker report every seeded task as "already covered by the plan" — it went red
    the first time it was right about anything, which is the failure mode that teaches people
    to ignore a gate. Coverage therefore stops at the `## Phase 7` heading.
    """
    text = read(PLAN)
    cut = re.search(r"^## Phase 7\b", text, re.MULTILINE)
    return set(LCODE.findall(text[: cut.start()] if cut else text))


def seeded_tasks() -> dict[str, set[str]]:
    """Map task id -> L-codes named in the heading of each seeded Phase 7+ task section.

    A seeded task whose heading disagrees with its scope row means the scope and the plan have
    drifted, and the plan is what a lane executes.
    """
    text = read(PLAN)
    cut = re.search(r"^## Phase 7\b", text, re.MULTILINE)
    if not cut:
        return {}
    return {
        m.group(1): set(LCODE.findall(m.group(2)))
        for m in re.finditer(r"^### Task (\d+\.\d+):(.*)$", text[cut.start() :], re.MULTILINE)
    }


def routes() -> dict[str, str]:
    """Map task id -> the route named in the last cell of its scope row.

    Phase 11's table has no route column because every row in it is MiniMax's; those rows
    fall back to `minimax-m3` rather than being reported as unrouted.
    """
    out: dict[str, str] = {}
    for line in read(SCOPE).splitlines():
        m = TASK_ROW.match(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        out[m.group(1)] = cells[-1].strip("` ") if len(cells) >= 4 else "minimax-m3"
    return out


def declared_route_totals() -> dict[str, int]:
    """The counts the scope document's own routing-summary table claims."""
    out: dict[str, int] = {}
    for line in read(SCOPE).splitlines():
        m = ROUTE_SUMMARY_ROW.match(line)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


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

    # Drift between the scope row and the seeded task section. The plan is what a lane
    # executes, so a seeded heading that names different items than its scope row silently
    # rescopes the work.
    seeded = seeded_tasks()
    for task, heading_codes in sorted(seeded.items()):
        scoped = set(per_task.get(task, []))
        if not scoped:
            findings.append(f"task {task} is seeded into the plan but appears in no scope row")
        elif heading_codes != scoped:
            findings.append(
                f"task {task} is seeded with {sorted(heading_codes) or 'no items'} "
                f"but scoped with {sorted(scoped)}"
            )

    # The routing-summary table is prose about the rows above it, and prose about a count is
    # exactly what drifts. It shipped saying 38 GLM / 23 Opus when the rows said 34 / 27, and
    # a lane prompt repeated both wrong numbers. Count the rows instead.
    actual: dict[str, int] = {}
    for route in routes().values():
        actual[route] = actual.get(route, 0) + 1
    declared = declared_route_totals()
    for route, count in sorted(actual.items()):
        if route not in declared:
            findings.append(f"route '{route}' has {count} rows but no line in the routing summary")
        elif declared[route] != count:
            findings.append(
                f"routing summary claims {declared[route]} tasks for '{route}' "
                f"but {count} rows say so"
            )
    for route in sorted(set(declared) - set(actual)):
        findings.append(f"routing summary lists '{route}' but no row is routed to it")

    print(f"phase scope: {len(seeded)} of {len(per_task)} tasks seeded into the plan")
    print(
        "phase scope: routes "
        + ", ".join(f"{r} {c}" for r, c in sorted(actual.items(), key=lambda kv: -kv[1]))
    )
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

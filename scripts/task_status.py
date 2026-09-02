#!/usr/bin/env python3
"""Derive implementation-plan task status from git. Never from a hand-edited table.

This repository has an eight-incident history of prose claims outrunning the code,
so a status board that a human maintains is a status board that will lie. Everything
here is derived:

  task list   <- the plan file's `### Task N.M:` headings
  state       <- git: does the branch exist, is it an ancestor of origin/main
  evidence    <- docs/task-evidence/task-N.M.md must exist before a task reads DONE
  routing     <- docs/task-routing.json (intent only: who, and what blocks what)

A task is DONE only when its branch is merged AND its exit-gate evidence file exists.
Merged without evidence is reported as UNEVIDENCED, which is a defect, not a state.

Usage:
    python scripts/task_status.py            # print the board
    python scripts/task_status.py --write    # regenerate docs/TASK-STATUS.md
    python scripts/task_status.py --check    # CI: fail if the file is stale
    python scripts/task_status.py --next     # what is runnable right now, and by whom
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PLAN = REPO / "docs/superpowers/plans/2026-09-02-native-ai-platform-os-implementation.md"
ROUTING = REPO / "docs/task-routing.json"
BOARD = REPO / "docs/TASK-STATUS.md"

TASK_RE = re.compile(r"^### Task (\d+\.\d+):\s*(.+?)\s*$", re.MULTILINE)
STEP_RE = re.compile(r"^- \[ \] \*\*Step\b", re.MULTILINE)


def git(*args: str) -> str:
    """Run git and return stdout, or '' on any failure. Never raises."""
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO), *args],
            capture_output=True, text=True, timeout=30, check=False,
        )
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


@dataclass
class Task:
    task_id: str
    phase: str
    title: str
    steps: int
    expanded: bool
    owner: str
    branch: str
    exists: bool
    merged: bool
    sha: str
    evidence: bool
    blocked_by: list[str]

    @property
    def state(self) -> str:
        if self.merged and self.evidence:
            return "DONE"
        if self.merged and not self.evidence:
            return "UNEVIDENCED"          # merged with no exit-gate proof: a defect
        if self.exists:
            return "IN-FLIGHT"
        if self.blocked_by:
            return "BLOCKED"
        if not self.expanded:
            return "NEEDS-EXPANSION"
        return "READY"


def load_tasks() -> list[Task]:
    if not PLAN.exists():
        sys.exit(f"plan not found: {PLAN}")
    text = PLAN.read_text(encoding="utf-8")
    routing = json.loads(ROUTING.read_text(encoding="utf-8")) if ROUTING.exists() else {}

    owners: dict[str, str] = routing.get("routing", {})
    gates: dict[str, dict] = routing.get("gates", {})
    spine: dict[str, list[str]] = routing.get("phase_spine", {})
    needs_expansion = set(routing.get("expansion_required", []))
    convention = routing.get("branch_convention", "impl/task-{id}")
    evidence_dir = REPO / routing.get("evidence_dir", "docs/task-evidence")

    # Branch and merge state, read once.
    all_branches = set(
        b.strip().lstrip("* ").replace("remotes/origin/", "")
        for b in git("branch", "-a", "--format=%(refname:short)").splitlines()
        if b.strip()
    )
    merged_into_main = set(
        b.strip().lstrip("* ").replace("remotes/origin/", "")
        for b in git("branch", "-a", "--merged", "origin/main",
                     "--format=%(refname:short)").splitlines()
        if b.strip()
    )

    matches = list(TASK_RE.finditer(text))
    tasks: list[Task] = []
    for i, m in enumerate(matches):
        task_id, title = m.group(1), m.group(2)
        body = text[m.end(): matches[i + 1].start() if i + 1 < len(matches) else len(text)]
        phase = task_id.split(".")[0]

        # Match any branch carrying this task id as a segment, because the plan's own
        # steps use `feat/task-0.1-reputation-workspace` while other lanes may use a
        # bare `impl/task-0.1`. Matching a single literal would have reported every
        # task as unstarted forever, which is the failure this whole board exists to
        # prevent, so the match is deliberately loose and the convention advisory.
        pattern = re.compile(rf"(?:^|/)task-{re.escape(task_id)}(?:-|$)")
        found = sorted(b for b in all_branches if pattern.search(b))
        branch = found[0] if found else convention.format(id=task_id)
        exists = bool(found)
        merged = exists and any(pattern.search(b) for b in merged_into_main)
        sha = git("rev-parse", "--short", branch) if exists else ""

        # A task is blocked by an explicit gate, or by its phase's predecessors.
        blocked: list[str] = []
        for gate_id, gate in gates.items():
            if task_id in gate.get("blocks", []):
                blocked.append(f"task {gate_id}")
        for pre in spine.get(phase, []):
            blocked.append(f"phase {pre}")

        tasks.append(Task(
            task_id=task_id,
            phase=phase,
            title=title,
            steps=len(STEP_RE.findall(body)),
            expanded=phase not in needs_expansion,
            owner=owners.get(task_id, "unassigned"),
            branch=branch,
            exists=exists,
            merged=merged,
            sha=sha,
            evidence=(evidence_dir / f"task-{task_id}.md").exists(),
            blocked_by=blocked,
        ))
    return tasks


def resolve_blocks(tasks: list[Task]) -> None:
    """Drop satisfied blockers so BLOCKED means actually blocked, now."""
    done = {t.task_id for t in tasks if t.state == "DONE"}
    phase_done = {
        p for p in {t.phase for t in tasks}
        if all(t.state == "DONE" for t in tasks if t.phase == p)
    }
    for t in tasks:
        t.blocked_by = [
            b for b in t.blocked_by
            if not (b.startswith("task ") and b[5:] in done)
            and not (b.startswith("phase ") and b[6:] in phase_done)
        ]


def render(tasks: list[Task]) -> str:
    counts: dict[str, int] = {}
    for t in tasks:
        counts[t.state] = counts.get(t.state, 0) + 1
    total_steps = sum(t.steps for t in tasks)
    done_steps = sum(t.steps for t in tasks if t.state == "DONE")

    out = [
        "# Implementation task status",
        "",
        "> **Generated by `scripts/task_status.py`. Do not edit by hand.**",
        "> State is derived from git — branch existence and ancestry of `origin/main` —",
        "> and from the presence of an exit-gate evidence file. It cannot say DONE ahead",
        "> of the evidence, which is the one job `docs/W1-delivery-gaps.md` names for a",
        "> ledger. Regenerate with `python scripts/task_status.py --write`.",
        "",
        f"**{len(tasks)} tasks · {total_steps} steps · {done_steps} steps landed**",
        "",
        "| State | Count | Meaning |",
        "|---|---|---|",
        f"| DONE | {counts.get('DONE', 0)} | Merged into `origin/main` **and** exit-gate evidence recorded |",
        f"| UNEVIDENCED | {counts.get('UNEVIDENCED', 0)} | Merged with no evidence file. **This is a defect, not a state.** |",
        f"| IN-FLIGHT | {counts.get('IN-FLIGHT', 0)} | Branch exists, not yet merged |",
        f"| READY | {counts.get('READY', 0)} | Expanded, unblocked, nobody has started it |",
        f"| NEEDS-EXPANSION | {counts.get('NEEDS-EXPANSION', 0)} | Task structure exists; Step-0 detail not yet captured |",
        f"| BLOCKED | {counts.get('BLOCKED', 0)} | A predecessor has not landed |",
        "",
        "| Task | Ph | Owner | State | Steps | Branch | SHA | Blocked by |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for t in tasks:
        blockers = ", ".join(t.blocked_by) if t.blocked_by else "—"
        title = t.title if len(t.title) <= 52 else t.title[:49] + "..."
        out.append(
            f"| **{t.task_id}** {title} | {t.phase} | `{t.owner}` | "
            f"{t.state} | {t.steps or '—'} | `{t.branch}` | "
            f"{t.sha or '—'} | {blockers} |"
        )

    runnable = [t for t in tasks if t.state == "READY"]
    out += ["", "## Runnable right now", ""]
    if runnable:
        for t in runnable:
            out.append(f"- **Task {t.task_id}** — {t.title} → `{t.owner}`")
    else:
        out.append("_Nothing is unblocked and expanded. Expand a phase, or land a predecessor._")

    unev = [t for t in tasks if t.state == "UNEVIDENCED"]
    if unev:
        out += ["", "## Merged without evidence — fix before trusting this board", ""]
        for t in unev:
            out.append(f"- **Task {t.task_id}** merged at `{t.sha}` with no "
                       f"`docs/task-evidence/task-{t.task_id}.md`.")
    out.append("")
    return "\n".join(out)


def main() -> int:
    # Windows consoles default to cp1252, which cannot encode the arrows and box
    # characters this board prints. Reconfigure rather than requiring the caller to
    # set PYTHONIOENCODING: a tool that only works with the right env var set is a
    # tool that will fail in CI on the one platform nobody tests.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--write", action="store_true", help="regenerate docs/TASK-STATUS.md")
    ap.add_argument("--check", action="store_true", help="fail if the board is stale")
    ap.add_argument("--next", action="store_true", help="print only what is runnable")
    args = ap.parse_args()

    tasks = load_tasks()
    resolve_blocks(tasks)
    board = render(tasks)

    if args.next:
        for t in tasks:
            if t.state == "READY":
                print(f"{t.task_id:5s} {t.owner:16s} {t.title}")
        return 0

    if args.check:
        current = BOARD.read_text(encoding="utf-8") if BOARD.exists() else ""
        if current != board:
            print("TASK-STATUS.md is stale or hand-edited.", file=sys.stderr)
            print("Run: python scripts/task_status.py --write", file=sys.stderr)
            return 1
        unev = [t.task_id for t in tasks if t.state == "UNEVIDENCED"]
        if unev:
            print(f"merged without exit-gate evidence: {', '.join(unev)}", file=sys.stderr)
            return 1
        print("task status current; no unevidenced merges")
        return 0

    if args.write:
        BOARD.write_text(board, encoding="utf-8")
        print(f"wrote {BOARD.relative_to(REPO)}")
        return 0

    print(board)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

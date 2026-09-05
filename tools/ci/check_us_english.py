#!/usr/bin/env python3
"""Refuse a Britishism on a line this branch ADDED, using the canonical matcher.

Two parts, and only one of them is ours.

The MATCHING is `verify-us-english.mjs`, vendored byte-for-byte from
`M:/Project AumOS - Linkedin Blitzkrieg/scripts/verify-us-english.mjs`, which is the cross-project
arbiter for every public surface. It is vendored rather than invoked in place because CI runs on a
host where that path does not exist. Keep the copy byte-identical; `test_check_us_english.py` asserts
the behavior a hand-rolled matcher got wrong.

The SCOPING is ours: only lines the branch adds. That is the same ratchet idiom
`check_invariant_ratchet.py` uses, and it matters because one file this repository touches already
carries sixteen pre-existing Britishisms. Failing on those makes the gate unpassable, and an
unpassable gate teaches people to skip gates. A branch answers for the lines it adds.

Why the matcher is not reimplemented here, recorded because the mistake was made and shipped: the
first version of this file vendored the word LIST and wrote its own regex over the stems. On a
four-line corpus of ordinary American English it produced six false positives -- `analysis`,
`specialist`, `specialism`, `organism`, `synthesis` -- and missed the one real Britishism, because
`organism` matched the `organis` stem first and suppressed `organisation`. The canonical script gets
that corpus exactly right, because an `-is` stem there may only be followed by a specific suffix set
(`ation`, `ing`, `ed`, `es`, `ably`, and the rest). Those 794 lines are not boilerplate. Two readers
of one rule is the defect this repository keeps finding in itself; this file is not a second reader.

Usage:
    python tools/ci/check_us_english.py [base_ref]      # default base: origin/main
    python tools/ci/check_us_english.py --files a.md b.rs
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

# parents[2], not parents[1]: this file is tools/ci/, so parents[1] is tools/ and every
# repo-relative path from the diff failed its existence check -- the gate reported "ok" while
# scanning zero files. The "0 file(s)" in its own summary line was the only tell.
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATCHER = Path(__file__).resolve().parent / "verify-us-english.mjs"

# `    line   12  honour -> honor`
FINDING = re.compile(r"^\s*line\s+(\d+)\s+(\S+)\s*->\s*(\S+)\s*$")

# Only text a reader can see. A lock file or generated artifact is not a public surface.
TEXT_SUFFIXES = {".md", ".rs", ".py", ".js", ".mjs", ".ts", ".tsx", ".html", ".txt",
                 ".yml", ".yaml", ".toml", ".go", ".sh"}
SKIP_PARTS = {"__pycache__", "node_modules", "target", "vendor", ".git"}

# The vendored matcher IS the rejected forms, so it cannot be scanned for them.
SELF_REFERENTIAL = ("tools/ci/verify-us-english.mjs", "tools/ci/test_check_us_english.py")


def git(*args: str) -> str:
    out = subprocess.run(["git", *args], cwd=REPOSITORY_ROOT,
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    return out.stdout if out.returncode == 0 else ""


def wanted(path: str) -> bool:
    normalized = path.replace("\\", "/")
    if normalized.endswith(SELF_REFERENTIAL):
        return False
    if any(part in SKIP_PARTS for part in Path(normalized).parts):
        return False
    return Path(normalized).suffix.lower() in TEXT_SUFFIXES


def added_by_file(base: str) -> dict[str, set[int]]:
    """path -> the set of line numbers this branch adds, in the new file's numbering."""
    diff = git("diff", "--unified=0", f"{base}...HEAD")
    added: dict[str, set[int]] = {}
    path, line_no = "", 0
    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            path, line_no = raw[6:], 0
        elif raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            line_no = int(match.group(1)) if match else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            if wanted(path):
                added.setdefault(path, set()).add(line_no)
            line_no += 1
    return added


def scan(paths: list[str]) -> list[tuple[str, int, str, str]]:
    """Run the canonical matcher and return (path, line, british, american) for every finding."""
    if not MATCHER.exists():
        sys.exit(f"::error::missing vendored matcher: {MATCHER}")
    node = shutil.which("node")
    if not node:
        sys.exit("::error::node is required to run the vendored US-English matcher")
    out: list[tuple[str, int, str, str]] = []
    for path in paths:
        proc = subprocess.run([node, str(MATCHER), path], cwd=REPOSITORY_ROOT,
                              capture_output=True, text=True, encoding="utf-8", errors="replace")
        for raw in (proc.stdout + proc.stderr).splitlines():
            found = FINDING.match(raw)
            if found:
                out.append((path, int(found.group(1)), found.group(2), found.group(3)))
    return out


def main() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] == "--files":
        names = argv[1:]
        missing = [n for n in names if not (REPOSITORY_ROOT / n).exists() and not Path(n).exists()]
        if missing:
            print(f"::error::no such file: {', '.join(missing)}", file=sys.stderr)
            return 1
        hits = scan(names)
        scope = f"{len(names)} file(s), every line"
    else:
        base = argv[0] if argv else "origin/main"
        added = added_by_file(base)
        existing = [p for p in added if (REPOSITORY_ROOT / p).exists()]
        # Keep only findings on lines this branch actually added.
        total_added = sum(len(v) for v in added.values())
        # Self-check. A path bug once made every existence test fail, so this reported "ok" while
        # scanning zero files -- a gate that passes vacuously is worse than no gate, because it is
        # believed. If the diff produced lines but no file resolved, that is a defect in this script,
        # not a clean branch.
        if total_added and not existing:
            print(f"::error::us-english: {total_added} added line(s) resolved to 0 readable files; "
                  f"the paths from the diff do not exist under {REPOSITORY_ROOT}. This is a bug in "
                  f"this gate, not a passing branch.", file=sys.stderr)
            return 1
        hits = [h for h in scan(existing) if h[1] in added.get(h[0], set())]
        scope = f"{total_added} added line(s) across {len(existing)} file(s), since {base}"

    print(f"us-english: {scope}; matcher = vendored verify-us-english.mjs")
    if hits:
        for path, line, british, american in hits:
            print(f"::error::us-english: {path}:{line}: {british!r} -- use {american!r}")
        print(f"us-english: {len(hits)} Britishism(s) on added lines", file=sys.stderr)
        return 1
    print("us-english: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Refuse a Britishism on a line this branch ADDED. Public surfaces are US English.

The doctrine is machine-verified rather than eyeballed, and this repository had no gate for it: two
Britishisms reached a branch's `report.rs` doc comments in September 2026 and only an adversarial
reviewer caught them, precisely because nothing in `tools/ci/` looked.

Diff-scoped on purpose, which is the same ratchet idiom `check_invariant_ratchet.py` uses. One
touched file already carries sixteen pre-existing Britishisms; failing on those would make the gate
unpassable and teach people to skip it. A branch is answerable for the lines it adds.

The word list is DATA, vendored in `us-english-forms.json` from the canonical cross-project checker,
because CI runs on a host where that script's path does not exist. The provenance is recorded in that
file: if the two disagree, the canonical script wins and the data is re-extracted, never hand-edited.

Usage:
    python tools/ci/check_us_english.py [base_ref]      # default base: origin/main
    python tools/ci/check_us_english.py --files a.md b.rs
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FORMS_FILE = Path(__file__).resolve().parent / "us-english-forms.json"

# Carve-out 3 is code identifiers, and these two are genuine English rather than Britishisms.
# `forwards` is a verb ("the proxy forwards the call"); `analyses` is the plural of the noun
# `analysis`, which the `analys` stem would otherwise flag. Both are correct as written.
FALSE_POSITIVES = re.compile(r"\b(forwards|analyses)\b", re.IGNORECASE)

# Only text a reader can see. A .lock or generated file is not a public surface.
TEXT_SUFFIXES = {".md", ".rs", ".py", ".js", ".mjs", ".ts", ".tsx", ".html", ".txt", ".json",
                 ".yml", ".yaml", ".toml", ".go", ".sh"}
SKIP_PARTS = {"__pycache__", "node_modules", "target", "vendor", ".git"}

# Two files must CONTAIN the forms this gate rejects, or they cannot do their jobs: the vendored word
# list is those forms, and the gate's own tests must feed it a Britishism to prove it refuses one.
# Excluding them by name is narrow and stated; the alternative is a gate that cannot be tested.
SELF_REFERENTIAL = {
    "tools/ci/us-english-forms.json",
    "tools/ci/test_check_us_english.py",
}


def load_forms() -> tuple[list[tuple[str, str]], list[str]]:
    if not FORMS_FILE.exists():
        sys.exit(f"::error::missing word list: {FORMS_FILE}")
    data = json.loads(FORMS_FILE.read_text(encoding="utf-8"))
    return [tuple(pair) for pair in data["forms"]], data["proper_nouns"]


def git(*args: str) -> str:
    out = subprocess.run(["git", *args], cwd=REPOSITORY_ROOT,
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    return out.stdout if out.returncode == 0 else ""


def added_lines(base: str) -> list[tuple[str, int, str]]:
    """(path, line number in the new file, text) for every line this branch adds."""
    diff = git("diff", "--unified=0", f"{base}...HEAD")
    if not diff:
        return []
    rows: list[tuple[str, int, str]] = []
    path, line_no = "", 0
    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            path, line_no = raw[6:], 0
        elif raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            line_no = int(match.group(1)) if match else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            rows.append((path, line_no, raw[1:]))
            line_no += 1
    return rows


def wanted(path: str) -> bool:
    normalized = path.replace("\\", "/")
    if normalized in SELF_REFERENTIAL or normalized.endswith(tuple(SELF_REFERENTIAL)):
        return False
    parts = Path(path).parts
    if any(p in SKIP_PARTS for p in parts):
        return False
    return Path(path).suffix.lower() in TEXT_SUFFIXES


def findings(rows, forms, proper_nouns) -> list[str]:
    out = []
    for path, line_no, text in rows:
        if not wanted(path):
            continue
        # Carve-out 3: a backtick span is code, an identifier, or a word quoted AS a word --
        # which is how a document about spelling discusses the spellings it rejects. Stripping
        # these means a real Britishism can hide inside backticks; that is the correct trade,
        # because the alternative flags every line that quotes one as an example.
        text_scanned = re.sub(r"`[^`]*`", " ", text)
        # Carve-out 2: a proper noun or cited title keeps its source spelling.
        scrubbed = text_scanned
        for noun in proper_nouns:
            scrubbed = re.sub(re.escape(noun), "", scrubbed, flags=re.IGNORECASE)
        scrubbed = FALSE_POSITIVES.sub("", scrubbed)
        # Every Britishism on the line, not just the first. A gate that reports one at a time
        # makes a fixer iterate, and each iteration is a full CI round trip.
        seen: list[str] = []
        for british, american in forms:
            pattern = rf"\b\w*{re.escape(british)}\w*"
            match = re.search(pattern, scrubbed, re.IGNORECASE)
            if not match:
                continue
            hit = match.group(0)
            if hit.lower() in seen:      # a longer stem already claimed this word
                continue
            seen.append(hit.lower())
            out.append(f"{path}:{line_no}: {hit!r} -- use the {american!r} form\n"
                       f"    {text.strip()[:140]}")
    return out


def main() -> int:
    forms, proper_nouns = load_forms()
    argv = sys.argv[1:]
    if argv and argv[0] == "--files":
        rows = []
        for name in argv[1:]:
            path = Path(name)
            if not path.exists():
                print(f"::error::no such file: {name}", file=sys.stderr)
                return 1
            for i, text in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                rows.append((name.replace("\\", "/"), i, text))
        scope = f"{len(argv) - 1} file(s), every line"
    else:
        base = argv[0] if argv else "origin/main"
        rows = added_lines(base)
        scope = f"lines added since {base}"

    hits = findings(rows, forms, proper_nouns)
    print(f"us-english: {len(rows)} candidate line(s) scanned ({scope}); "
          f"{len(forms)} forms, {len(proper_nouns)} proper nouns")
    if hits:
        for hit in hits:
            print(f"::error::us-english: {hit}")
        print(f"us-english: {len(hits)} Britishism(s) on added lines", file=sys.stderr)
        return 1
    print("us-english: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

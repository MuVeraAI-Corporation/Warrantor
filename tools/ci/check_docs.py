#!/usr/bin/env python3
"""Fail-closed structural and local-link validation for Warrantor documentation."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import unquote

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = REPOSITORY_ROOT / "docs" / "implementation" / "catalog.json"
REQUIRED_DOCUMENTS = (
    "README.md",
    "docs/00-reconciliation-matrix.md",
    "docs/01-vision-and-portfolio.md",
    "docs/02-architecture.md",
    "docs/cross-cutting/17-data-classification-privacy.md",
    "docs/cross-cutting/18-developer-experience.md",
    "docs/cross-cutting/19-inter-component-protocol.md",
    "docs/implementation/catalog.json",
    "docs/implementation/tracker-state.json",
)
REQUIRED_RFC_HEADINGS = (
    "Background",
    "Goals",
    "Detailed Design",
    "Dependencies",
    "Threat Model",
    "API",
    "Testing",
    "Deployment",
    "Milestones",
)
MARKDOWN_LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\((?P<destination>[^)]+)\)")
EXTERNAL_SCHEMES = ("data:", "http://", "https://", "mailto:", "tel:")


@dataclass(frozen=True)
class DocumentationIssue:
    """One actionable documentation validation failure."""

    path: str
    line: int
    message: str


def relative_path(path: Path) -> str:
    """Return a stable POSIX repository-relative path."""

    return path.relative_to(REPOSITORY_ROOT).as_posix()


def markdown_files() -> list[Path]:
    """Discover maintained Markdown surfaces while excluding generated dependencies."""

    roots = [
        REPOSITORY_ROOT / "README.md",
        REPOSITORY_ROOT / "docs",
        REPOSITORY_ROOT / "specs",
    ]
    files: set[Path] = set()
    for root in roots:
        if root.is_file():
            files.add(root)
        elif root.is_dir():
            files.update(path for path in root.rglob("*.md") if path.is_file())

    # Restrict to TRACKED files so this gate agrees with CI.
    #
    # Walking the filesystem makes the verdict depend on untracked working-directory
    # contents, and it fails in both directions. Committed docs once referenced files
    # that existed only locally: this check passed and CI failed. Untracked docs later
    # referenced paths outside the repository: this check failed and CI passed. Neither
    # is a useful signal, and a gate that disagrees with the one that blocks a merge
    # teaches people to ignore it.
    tracked = tracked_markdown()
    if tracked is not None:
        files &= tracked
    return sorted(files, key=relative_path)


def tracked_markdown() -> set[Path] | None:
    """Every Markdown file git is tracking, or None if git is unavailable.

    Returning None (rather than an empty set) on failure keeps this check working in a
    source tarball with no .git directory -- it falls back to the filesystem walk rather
    than silently reporting zero documents, which would look like a pass.
    """

    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z", "*.md"],
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            check=False,
        )
    except (OSError, ValueError):
        return None
    if completed.returncode != 0:
        return None
    names = completed.stdout.decode("utf-8", "replace").split("\0")
    return {REPOSITORY_ROOT / name for name in names if name}


def destination_path(source_path: Path, raw_destination: str) -> Path | None:
    """Resolve a Markdown destination to a local path, or return None for non-file links."""

    destination = raw_destination.strip()
    if destination.startswith("<") and ">" in destination:
        destination = destination[1 : destination.index(">")]
    else:
        destination = destination.split(maxsplit=1)[0]
    destination = unquote(destination.split("#", 1)[0].split("?", 1)[0])
    if not destination or destination.lower().startswith(EXTERNAL_SCHEMES):
        return None
    if destination.startswith("/"):
        candidate = REPOSITORY_ROOT / destination.lstrip("/")
    else:
        candidate = source_path.parent / destination
    return candidate.resolve()


def validate_local_links(path: Path) -> list[DocumentationIssue]:
    """Validate every local Markdown link in one file."""

    issues: list[DocumentationIssue] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        for match in MARKDOWN_LINK_PATTERN.finditer(line):
            candidate = destination_path(path, match.group("destination"))
            if candidate is None:
                continue
            try:
                candidate.relative_to(REPOSITORY_ROOT)
            except ValueError:
                issues.append(
                    DocumentationIssue(
                        relative_path(path),
                        line_number,
                        f"link escapes repository: {candidate}",
                    )
                )
                continue
            if not candidate.exists():
                issues.append(
                    DocumentationIssue(
                        relative_path(path),
                        line_number,
                        f"missing local link target: {candidate.relative_to(REPOSITORY_ROOT).as_posix()}",
                    )
                )
    return issues


def validate_rfc(path: Path) -> list[DocumentationIssue]:
    """Require the canonical RFC title and section contract."""

    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    issues: list[DocumentationIssue] = []
    title = lines[0] if lines else ""
    if not title.startswith("# ") or "RFC" not in title:
        issues.append(
            DocumentationIssue(
                relative_path(path), 1, "RFC title must be an H1 containing 'RFC'"
            )
        )
    headings = {line[3:].strip().lower() for line in lines if line.startswith("## ")}
    for required_heading in REQUIRED_RFC_HEADINGS:
        if not any(required_heading.lower() in heading for heading in headings):
            issues.append(
                DocumentationIssue(
                    relative_path(path),
                    1,
                    f"missing RFC section matching: {required_heading}",
                )
            )
    return issues


def load_catalog_entries() -> list[dict[str, object]]:
    """Load the catalogue entries as validated JSON objects."""

    parsed: object = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("catalog root must be an object")
    entries = parsed.get("entries")
    if not isinstance(entries, list):
        raise ValueError("catalog entries must be an array")
    result: list[dict[str, object]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not all(
            isinstance(key, str) for key in entry
        ):
            raise ValueError(f"catalog entry {index} must be an object")
        result.append(cast(dict[str, object], entry))
    return result


def validate_catalog() -> list[DocumentationIssue]:
    """Validate counts, uniqueness, and every claimed catalogue artifact."""

    issues: list[DocumentationIssue] = []
    try:
        entries = load_catalog_entries()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return [DocumentationIssue(relative_path(CATALOG_PATH), 1, str(error))]
    identifiers = [entry.get("id") for entry in entries]
    components = [entry for entry in entries if entry.get("kind") == "component"]
    protocols = [entry for entry in entries if entry.get("kind") == "protocol"]
    # `support` entries are first-party source directories that are not part of the
    # canonical 54-component portfolio but must still be tracked, so that the
    # bidirectional integrity check in generate_tracker.py can pass. Their count is
    # not fixed -- it changes whenever a support directory is added or promoted.
    support = [entry for entry in entries if entry.get("kind") == "support"]
    unknown_kinds = sorted(
        {
            str(entry.get("kind"))
            for entry in entries
            if entry.get("kind") not in {"component", "protocol", "support"}
        }
    )
    if len(components) != 54 or len(protocols) != 12 or unknown_kinds:
        issues.append(
            DocumentationIssue(
                relative_path(CATALOG_PATH),
                1,
                "catalogue must contain exactly 54 components and 12 protocols plus any "
                f"number of support rows; found {len(components)} components, "
                f"{len(protocols)} protocols, {len(support)} support"
                + (f", unknown kinds {unknown_kinds}" if unknown_kinds else ""),
            )
        )
    if not all(
        isinstance(identifier, str) and identifier for identifier in identifiers
    ):
        issues.append(
            DocumentationIssue(
                relative_path(CATALOG_PATH),
                1,
                "every catalogue row needs a non-empty string ID",
            )
        )
    elif len(identifiers) != len(set(cast(list[str], identifiers))):
        issues.append(
            DocumentationIssue(
                relative_path(CATALOG_PATH), 1, "catalogue IDs must be unique"
            )
        )
    for entry in entries:
        identifier = entry.get("id", "unknown")
        paths: list[str] = []
        rfc = entry.get("rfc")
        if isinstance(rfc, str):
            paths.append(rfc)
        source_paths = entry.get("source_paths")
        if isinstance(source_paths, list):
            paths.extend(cast(list[str], source_paths))
        for claimed_path in paths:
            if (
                not isinstance(claimed_path, str)
                or not (REPOSITORY_ROOT / claimed_path).exists()
            ):
                issues.append(
                    DocumentationIssue(
                        relative_path(CATALOG_PATH),
                        1,
                        f"{identifier}: missing claimed artifact {claimed_path}",
                    )
                )
    return issues


def main() -> int:
    """Run every documentation contract and report all failures together."""

    issues: list[DocumentationIssue] = []
    for required_document in REQUIRED_DOCUMENTS:
        if not (REPOSITORY_ROOT / required_document).is_file():
            issues.append(
                DocumentationIssue(required_document, 1, "required document is missing")
            )
    files = markdown_files()
    for path in files:
        issues.extend(validate_local_links(path))
    rfc_paths = sorted(
        (REPOSITORY_ROOT / "docs" / "rfcs").glob("*.md"), key=relative_path
    )
    if not rfc_paths:
        issues.append(DocumentationIssue("docs/rfcs", 1, "no RFC documents found"))
    for path in rfc_paths:
        issues.extend(validate_rfc(path))
    issues.extend(validate_catalog())
    try:
        catalogue_rows = len(load_catalog_entries())
    except (OSError, ValueError, json.JSONDecodeError):
        catalogue_rows = 0

    for issue in issues:
        print(f"{issue.path}:{issue.line}: {issue.message}")
    if issues:
        print(f"RESULT: FAIL — {len(issues)} documentation issue(s)")
        return 1
    print(
        f"RESULT: PASS — {len(files)} Markdown files, {len(rfc_paths)} RFCs, "
        f"{catalogue_rows} catalogue rows, and all local links validated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

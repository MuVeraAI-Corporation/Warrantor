#!/usr/bin/env python3
"""Generate the exhaustive AumOS implementation tracker from canonical state."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = REPOSITORY_ROOT / "docs" / "implementation" / "catalog.json"
STATE_PATH = REPOSITORY_ROOT / "docs" / "implementation" / "tracker-state.json"
DEFAULT_OUTPUT_PATH = REPOSITORY_ROOT / "docs" / "implementation" / "tracker.json"

EXPECTED_COMPONENT_IDS = (
    "T1",
    "T2",
    "I1",
    "I2",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
    "R8",
    "C1-1",
    "C1-2",
    "C1-3",
    "C1-4",
    "C1-5",
    "S1",
    "S2",
    "S3",
    "S4",
    "S5",
    "S6",
    "S7",
    "S8",
    "S9",
    "A1",
    "A2",
    "A3",
    "A4",
    "A5",
    "A6",
    "A7",
    "A8",
    "N1",
    "N2",
    "N3",
    "N4",
    "F1",
    "F2",
    "F3",
    "F4",
    "X1",
    "X2",
    "X3",
    "X4",
    "X5",
    "X6",
    "X7",
    "X8",
    "X9",
    "X10",
    "X11",
    "E1",
)
EXPECTED_PROTOCOL_IDS = tuple(f"P{number}" for number in range(1, 13))
EXPECTED_FINDING_IDS = tuple(f"AUD-{number:03d}" for number in range(1, 13))
EXPECTED_GATE_IDS = tuple(f"G{number}" for number in range(1, 15))
ALLOWED_STATUSES = {
    "open",
    "in_progress",
    "implemented_pending_ci",
    "verified_local",
    "blocked_external",
    "complete",
}
SCAN_ROOTS = (
    ".github",
    "deploy",
    "go",
    "python",
    "rust",
    "specs",
    "tools",
    "typescript",
)
SCAN_SUFFIXES = {
    ".go",
    ".json",
    ".md",
    ".py",
    ".rs",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}
EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    "coverage",
    "dist",
    "node_modules",
    "target",
}
PENDING_PATTERN = re.compile(
    r"\b(?P<category>TODO|FIXME|HACK|stub(?:bed)?|mock(?:ed)?|placeholder|deferred|"
    r"future work|not implemented|task\s+0[2-8])\b",
    re.IGNORECASE,
)
CHECKBOX_PATTERN = re.compile(r"^\s*-\s*\[(?P<state>[ xX])\]\s*(?P<text>.+?)\s*$")


@dataclass(frozen=True)
class PendingMarker:
    """One exact source marker requiring implementation review."""

    path: str
    line: int
    category: str
    text: str


@dataclass(frozen=True)
class TaskCheckbox:
    """One acceptance or work checkbox from an RFC task document."""

    path: str
    line: int
    checked: bool
    text: str


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    return parser.parse_args()


def load_json_object(path: Path) -> dict[str, object]:
    """Load a JSON object and reject non-object roots."""

    parsed: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict) or not all(isinstance(key, str) for key in parsed):
        raise ValueError(f"{path}: expected a JSON object")
    return cast(dict[str, object], parsed)


def required_object_list(
    record: dict[str, object], key: str, path: Path
) -> list[dict[str, object]]:
    """Return a required list of string-keyed objects."""

    value = record.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{path}: {key!r} must be an array")
    result: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or not all(
            isinstance(item_key, str) for item_key in item
        ):
            raise ValueError(f"{path}: {key}[{index}] must be an object")
        result.append(cast(dict[str, object], item))
    return result


def required_string(record: dict[str, object], key: str, context: str) -> str:
    """Return a required non-empty string."""

    value = record.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context}: {key!r} must be a non-empty string")
    return value


def validate_exact_ids(
    actual_ids: list[str], expected_ids: tuple[str, ...], label: str
) -> None:
    """Require a collection to contain each canonical ID exactly once."""

    if len(actual_ids) != len(set(actual_ids)):
        raise ValueError(f"{label}: duplicate IDs detected")
    if set(actual_ids) != set(expected_ids):
        missing = sorted(set(expected_ids) - set(actual_ids))
        unexpected = sorted(set(actual_ids) - set(expected_ids))
        raise ValueError(f"{label}: missing={missing}, unexpected={unexpected}")


def validate_catalog(
    catalog: dict[str, object],
) -> tuple[list[dict[str, object]], list[str]]:
    """Validate the canonical 54+12 catalogue and return missing artifact paths."""

    entries = required_object_list(catalog, "entries", CATALOG_PATH)
    components = [entry for entry in entries if entry.get("kind") == "component"]
    protocols = [entry for entry in entries if entry.get("kind") == "protocol"]
    validate_exact_ids(
        [required_string(entry, "id", "catalog entry") for entry in components],
        EXPECTED_COMPONENT_IDS,
        "component catalogue",
    )
    validate_exact_ids(
        [required_string(entry, "id", "catalog entry") for entry in protocols],
        EXPECTED_PROTOCOL_IDS,
        "protocol catalogue",
    )

    missing_artifacts: list[str] = []
    for entry in entries:
        identifier = required_string(entry, "id", "catalog entry")
        status = required_string(entry, "status", identifier)
        source_paths = entry.get("source_paths")
        if not isinstance(source_paths, list) or not all(
            isinstance(path, str) for path in source_paths
        ):
            raise ValueError(f"{identifier}: source_paths must be a string array")
        if status == "reference_implementation" and not source_paths:
            raise ValueError(
                f"{identifier}: reference implementation has no source path"
            )
        if status == "unimplemented" and source_paths:
            raise ValueError(
                f"{identifier}: unimplemented entry must not claim source paths"
            )
        for relative_path in cast(list[str], source_paths):
            if not (REPOSITORY_ROOT / relative_path).exists():
                missing_artifacts.append(f"{identifier}: {relative_path}")
        rfc = entry.get("rfc")
        if rfc is not None:
            if not isinstance(rfc, str):
                raise ValueError(f"{identifier}: rfc must be a string or null")
            if not (REPOSITORY_ROOT / rfc).is_file():
                missing_artifacts.append(f"{identifier}: {rfc}")
    return entries, sorted(missing_artifacts)


# Source directories that are deliberately outside the component catalogue.
# Anything not listed here and not claimed by an entry is a governance gap:
# untracked code in a security substrate is worse than absent code, because
# nothing reviews it and no release gate covers it.
UNCATALOGUED_ALLOWLIST: frozenset[str] = frozenset(
    {
        # Generated protocol bindings -- covered by tools/protocols/generate.py --check
        # and by the protocol vector suite, not by a component RFC.
        "rust/protocol-contracts",
        "python/protocol_contracts",
        "go/protocol-contracts",
        "typescript/protocol-contracts",
        # Generated protobuf/tonic bindings for the contract plane.
        "rust/warrantor-api",
    }
)


def discover_source_directories() -> list[str]:
    """Every directory on disk that holds first-party source for a language stack."""

    found: list[str] = []
    for language, marker in (
        ("rust", "Cargo.toml"),
        ("go", "go.mod"),
        ("python", "pyproject.toml"),
        ("typescript", "package.json"),
    ):
        root = REPOSITORY_ROOT / language
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir()):
            if not child.is_dir() or child.name in {"node_modules", "target", "dist"}:
                continue
            if child.name.startswith(".") or (child / marker).is_file():
                if child.name.startswith("."):
                    continue
                found.append(f"{language}/{child.name}")
    return found


def find_unclaimed_sources(entries: list[dict[str, object]]) -> list[str]:
    """Return source directories that no catalogue entry claims.

    This is the reverse of ``missing_artifacts``. Checking only that claimed paths
    exist is vacuous -- it cannot detect code the catalogue has never heard of. Both
    directions are required for the integrity claim to mean anything.
    """

    claimed: set[str] = set()
    for entry in entries:
        for relative_path in cast(list[str], entry.get("source_paths") or []):
            claimed.add(relative_path.replace("\\", "/").rstrip("/"))
    return sorted(
        directory
        for directory in discover_source_directories()
        if directory not in claimed and directory not in UNCATALOGUED_ALLOWLIST
    )


def validate_state(state: dict[str, object]) -> None:
    """Validate required finding/gate coverage and status vocabulary."""

    findings = required_object_list(state, "audit_findings", STATE_PATH)
    gates = required_object_list(state, "release_gates", STATE_PATH)
    workstreams = required_object_list(state, "workstreams", STATE_PATH)
    validate_exact_ids(
        [required_string(finding, "id", "audit finding") for finding in findings],
        EXPECTED_FINDING_IDS,
        "audit findings",
    )
    validate_exact_ids(
        [required_string(gate, "id", "release gate") for gate in gates],
        EXPECTED_GATE_IDS,
        "release gates",
    )
    if len(workstreams) != 8:
        raise ValueError(f"workstreams: expected 8, found {len(workstreams)}")
    for collection_name, collection in (
        ("finding", findings),
        ("gate", gates),
        ("workstream", workstreams),
    ):
        for item in collection:
            identifier = required_string(item, "id", collection_name)
            status = required_string(item, "status", identifier)
            if status not in ALLOWED_STATUSES:
                raise ValueError(f"{identifier}: unsupported status {status!r}")


def relative_path(path: Path) -> str:
    """Return a stable POSIX repository-relative path."""

    return path.relative_to(REPOSITORY_ROOT).as_posix()


def eligible_source_files() -> list[Path]:
    """Discover bounded, reviewable source/configuration files."""

    files: list[Path] = []
    for root_name in SCAN_ROOTS:
        root = REPOSITORY_ROOT / root_name
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
                continue
            if EXCLUDED_PARTS.intersection(path.parts):
                continue
            if path.name in {"package-lock.json", "tracker.json"}:
                continue
            files.append(path)
    return sorted(files, key=relative_path)


def discover_pending_markers() -> list[PendingMarker]:
    """Enumerate explicit pending/mock/stub markers without truncation."""

    markers: list[PendingMarker] = []
    for path in eligible_source_files():
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            match = PENDING_PATTERN.search(line)
            if match is None:
                continue
            markers.append(
                PendingMarker(
                    path=relative_path(path),
                    line=line_number,
                    category=match.group("category").lower(),
                    text=line.strip()[:500],
                )
            )
    return markers


def discover_task_checkboxes() -> tuple[list[str], list[TaskCheckbox]]:
    """Enumerate every RFC task file and every checkbox inside it."""

    task_paths = sorted(
        (REPOSITORY_ROOT / "docs" / "rfcs").glob("*/tasks/*.md"),
        key=relative_path,
    )
    checkboxes: list[TaskCheckbox] = []
    for path in task_paths:
        for line_number, line in enumerate(
            path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
        ):
            match = CHECKBOX_PATTERN.match(line)
            if match is None:
                continue
            checkboxes.append(
                TaskCheckbox(
                    path=relative_path(path),
                    line=line_number,
                    checked=match.group("state").lower() == "x",
                    text=match.group("text"),
                )
            )
    return [relative_path(path) for path in task_paths], checkboxes


def git_value(arguments: list[str]) -> str | None:
    """Read optional Git metadata without making tracker generation depend on Git."""

    completed = subprocess.run(
        ["git", *arguments],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and value else None


def build_tracker() -> dict[str, object]:
    """Build and validate the complete machine-readable tracker document."""

    catalog = load_json_object(CATALOG_PATH)
    state = load_json_object(STATE_PATH)
    entries, missing_artifacts = validate_catalog(catalog)
    unclaimed_sources = find_unclaimed_sources(entries)
    validate_state(state)
    markers = discover_pending_markers()
    task_files, checkboxes = discover_task_checkboxes()
    checked_count = sum(item.checked for item in checkboxes)
    return {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "repository": {
            "commit": git_value(["rev-parse", "HEAD"]),
            "branch": git_value(["branch", "--show-current"]),
            "dirty": git_value(["status", "--porcelain"]) not in {None, ""},
        },
        "objective": state["objective"],
        "status_definitions": state["status_definitions"],
        "summary": {
            "catalog_entries": len(entries),
            "implementable_components": len(EXPECTED_COMPONENT_IDS),
            "protocols": len(EXPECTED_PROTOCOL_IDS),
            "missing_catalog_artifacts": len(missing_artifacts),
            "audit_findings": len(EXPECTED_FINDING_IDS),
            "release_gates": len(EXPECTED_GATE_IDS),
            "task_files": len(task_files),
            "task_checkboxes": len(checkboxes),
            "task_checkboxes_checked": checked_count,
            "task_checkboxes_open": len(checkboxes) - checked_count,
            "explicit_pending_markers": len(markers),
        },
        "catalog_integrity": {
            # Bidirectional. `missing_artifacts` catches catalogue entries pointing at
            # paths that do not exist; `unclaimed_sources` catches source directories
            # the catalogue has never heard of. Passing only the first is vacuous.
            "passed": not missing_artifacts and not unclaimed_sources,
            "missing_artifacts": missing_artifacts,
            "unclaimed_sources": unclaimed_sources,
        },
        "catalog": entries,
        "audit_findings": state["audit_findings"],
        "release_gates": state["release_gates"],
        "workstreams": state["workstreams"],
        "inventory": {
            "scan_roots": list(SCAN_ROOTS),
            "pending_markers": [asdict(marker) for marker in markers],
            "task_files": task_files,
            "task_checkboxes": [asdict(checkbox) for checkbox in checkboxes],
        },
    }


def main() -> int:
    """Generate the tracker or fail on catalogue/state integrity errors."""

    arguments = parse_arguments()
    try:
        tracker = build_tracker()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"tracker generation failed: {error}")
        return 1
    output_path = arguments.output.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(tracker, indent=2) + "\n", encoding="utf-8")
    summary = cast(dict[str, object], tracker["summary"])
    print(
        "tracker generated: "
        f"{summary['catalog_entries']} catalogue rows, "
        f"{summary['task_files']} task files, "
        f"{summary['task_checkboxes_open']} open task checkboxes, "
        f"{summary['explicit_pending_markers']} explicit source markers"
    )
    print(f"output: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

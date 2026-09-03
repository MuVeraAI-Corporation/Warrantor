#!/usr/bin/env python3
"""Count the workspace crates the `warrantor` binary can reach, and refuse to let it fall.

The progress metric this repository has learned to distrust is "crates completed". The one it
trusts is "crates a user can reach from the command line", because a crate that nothing links is
a test suite, not a capability. This script measures the second number from the manifests alone
(no cargo, no protoc, no network), records it in a versioned JSON file, and fails CI when a change
would lower it. It can only go up: that is the ratchet.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = REPOSITORY_ROOT / "rust"
FLOOR_PATH = REPOSITORY_ROOT / "evidence" / "wiring-coverage.json"
README_PATH = REPOSITORY_ROOT / "README.md"
BINARY_CRATE = "warrantor-warrant"
RECORD_FORMAT = "warrantor.wiring-coverage/1"

# Only `[dependencies]` (and its per-target form) puts code into the binary a user runs.
# `[dev-dependencies]` compile for tests and `[build-dependencies]` run on the build host; a crate
# reachable only through those is exactly the "tested in isolation, called by nothing" case this
# census exists to count as orphaned.
SHIPPING_TABLE = "dependencies"


@dataclass(frozen=True)
class WiringCensus:
    """One measurement of the workspace."""

    total: int
    reachable: int
    orphaned: list[str]
    edges: int


def read_manifest(path: Path) -> dict[str, object]:
    """Parse one Cargo.toml."""

    with path.open("rb") as handle:
        return tomllib.load(handle)


def workspace_members(workspace_root: Path) -> list[Path]:
    """Every member directory the workspace manifest declares, resolved."""

    manifest = read_manifest(workspace_root / "Cargo.toml")
    workspace = manifest.get("workspace")
    if not isinstance(workspace, dict) or not isinstance(workspace.get("members"), list):
        raise ValueError(f"{workspace_root / 'Cargo.toml'} declares no [workspace] members")
    return [(workspace_root / member).resolve() for member in workspace["members"]]


def package_name(crate_dir: Path) -> str:
    """The `[package].name` of a crate, which is what dependency edges are keyed on."""

    manifest = read_manifest(crate_dir / "Cargo.toml")
    package = manifest.get("package")
    if not isinstance(package, dict) or not isinstance(package.get("name"), str):
        raise ValueError(f"{crate_dir / 'Cargo.toml'} has no [package].name")
    return package["name"]


def shipping_path_dependencies(crate_dir: Path) -> list[Path]:
    """Resolved directories of every `path = ...` entry in the crate's shipping tables."""

    manifest = read_manifest(crate_dir / "Cargo.toml")
    tables: list[object] = [manifest.get(SHIPPING_TABLE, {})]
    targets = manifest.get("target", {})
    if isinstance(targets, dict):
        for target_table in targets.values():
            if isinstance(target_table, dict):
                tables.append(target_table.get(SHIPPING_TABLE, {}))
    found: list[Path] = []
    for table in tables:
        if not isinstance(table, dict):
            continue
        for spec in table.values():
            if isinstance(spec, dict) and isinstance(spec.get("path"), str):
                found.append((crate_dir / spec["path"]).resolve())
    return found


def dependency_graph(workspace_root: Path) -> dict[str, set[str]]:
    """Package name -> the workspace package names it links into its shipping build."""

    names = {crate_dir: package_name(crate_dir) for crate_dir in workspace_members(workspace_root)}
    graph: dict[str, set[str]] = {}
    for crate_dir, name in names.items():
        graph[name] = {
            names[dependency]
            for dependency in shipping_path_dependencies(crate_dir)
            if dependency in names
        }
    return graph


def reachable_crates(workspace_root: Path, binary_crate: str = BINARY_CRATE) -> set[str]:
    """Package names reachable from `binary_crate` over shipping path edges, itself included."""

    graph = dependency_graph(workspace_root)
    if binary_crate not in graph:
        raise KeyError(f"{binary_crate!r} is not a member of the workspace at {workspace_root}")
    seen = {binary_crate}
    queue: deque[str] = deque([binary_crate])
    while queue:
        for dependency in graph[queue.popleft()]:
            if dependency not in seen:
                seen.add(dependency)
                queue.append(dependency)
    return seen


def census(workspace_root: Path, binary_crate: str = BINARY_CRATE) -> WiringCensus:  # noqa: ARG001
    raise NotImplementedError


def load_floor(path: Path) -> int:
    raise NotImplementedError


def readme_renders(readme: Path, result: WiringCensus) -> bool:
    raise NotImplementedError


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError

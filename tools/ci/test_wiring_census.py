"""The wiring census, tested against a synthetic workspace and then against the real one."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import wiring_census
from wiring_census import (
    FLOOR_PATH,
    README_PATH,
    RECORD_FORMAT,
    WORKSPACE_ROOT,
    WiringCensus,
    census,
    load_floor,
    reachable_crates,
    readme_renders,
)


def write_crate(
    workspace: Path,
    directory: str,
    dependencies: tuple[str, ...] = (),
    dev_dependencies: tuple[str, ...] = (),
) -> None:
    """A minimal member crate whose package name is `w-<directory>`."""

    crate = workspace / directory
    crate.mkdir()
    lines = ["[package]", f'name = "w-{directory}"', 'version = "0.0.0"', "", "[dependencies]"]
    lines.extend(f'w-{dependency} = {{ path = "../{dependency}" }}' for dependency in dependencies)
    lines.extend(["", "[dev-dependencies]"])
    lines.extend(
        f'w-{dependency} = {{ path = "../{dependency}" }}' for dependency in dev_dependencies
    )
    (crate / "Cargo.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """cli -> core -> api; `island` links nothing; `dev-only` reaches cli only through tests."""

    members = ("cli", "core", "api", "island", "dev-only")
    rendered = ", ".join(f'"{member}"' for member in members)
    (tmp_path / "Cargo.toml").write_text(f"[workspace]\nmembers = [{rendered}]\n", encoding="utf-8")
    write_crate(tmp_path, "cli", dependencies=("core",))
    write_crate(tmp_path, "core", dependencies=("api",))
    write_crate(tmp_path, "api")
    write_crate(tmp_path, "island")
    write_crate(tmp_path, "dev-only", dev_dependencies=("cli",))
    return tmp_path


def test_reachable_follows_shipping_path_edges(workspace: Path) -> None:
    assert reachable_crates(workspace, "w-cli") == {"w-cli", "w-core", "w-api"}

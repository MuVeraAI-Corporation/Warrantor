"""The wiring census, tested against a synthetic workspace and then against the real one."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import wiring_census
from wiring_census import (
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


def test_dev_dependencies_do_not_make_a_crate_reachable(workspace: Path) -> None:
    result = census(workspace, "w-cli")
    assert "w-dev-only" in result.orphaned
    assert result.edges == 2


def test_census_counts_the_whole_workspace(workspace: Path) -> None:
    assert census(workspace, "w-cli") == WiringCensus(
        total=5, reachable=3, orphaned=["w-dev-only", "w-island"], edges=2
    )


def test_unknown_binary_crate_is_an_error(workspace: Path) -> None:
    with pytest.raises(KeyError, match="w-missing"):
        reachable_crates(workspace, "w-missing")


def write_readme(path: Path, result: WiringCensus) -> None:
    path.write_text(
        f"| Capabilities reachable from the CLI | **{result.reachable} of {result.total}** |\n",
        encoding="utf-8",
    )


def test_write_records_the_versioned_format(workspace: Path, tmp_path: Path) -> None:
    floor = tmp_path / "floor.json"
    exit_code = wiring_census.main(
        ["--workspace", str(workspace), "--binary-crate", "w-cli", "--floor", str(floor), "--write"]
    )
    record = json.loads(floor.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert record["format"] == RECORD_FORMAT
    assert record["binary_crate"] == "w-cli"
    assert record["reachable"] == 3
    assert record["orphaned"] == ["w-dev-only", "w-island"]


def test_ratchet_fails_when_reachable_drops_below_the_floor(
    workspace: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    floor = tmp_path / "floor.json"
    floor.write_text(json.dumps({"format": RECORD_FORMAT, "reachable": 4}), encoding="utf-8")
    readme = tmp_path / "README.md"
    write_readme(readme, census(workspace, "w-cli"))
    arguments = ["--workspace", str(workspace), "--binary-crate", "w-cli", "--floor", str(floor)]
    assert wiring_census.main([*arguments, "--readme", str(readme)]) == 1
    assert "::error::wiring ratchet: 3 reachable is below the recorded floor of 4" in (
        capsys.readouterr().out
    )


def test_ratchet_passes_at_the_floor_and_notices_above_it(
    workspace: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    floor = tmp_path / "floor.json"
    readme = tmp_path / "README.md"
    write_readme(readme, census(workspace, "w-cli"))
    arguments = [
        "--workspace",
        str(workspace),
        "--binary-crate",
        "w-cli",
        "--floor",
        str(floor),
        "--readme",
        str(readme),
    ]
    floor.write_text(json.dumps({"format": RECORD_FORMAT, "reachable": 3}), encoding="utf-8")
    assert wiring_census.main(arguments) == 0
    assert "::notice::" not in capsys.readouterr().out
    floor.write_text(json.dumps({"format": RECORD_FORMAT, "reachable": 2}), encoding="utf-8")
    assert wiring_census.main(arguments) == 0
    assert "::notice::wiring ratchet: 3 reachable exceeds the floor of 2" in (
        capsys.readouterr().out
    )


def test_a_record_in_another_format_is_refused(tmp_path: Path) -> None:
    floor = tmp_path / "floor.json"
    floor.write_text(json.dumps({"format": "warrantor.wiring-coverage/2", "reachable": 3}))
    with pytest.raises(ValueError, match="warrantor.wiring-coverage/2"):
        load_floor(floor)


def test_readme_must_render_the_current_number(
    workspace: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    floor = tmp_path / "floor.json"
    floor.write_text(json.dumps({"format": RECORD_FORMAT, "reachable": 3}), encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text("| Capabilities reachable from the CLI | **2 of 5** |\n", encoding="utf-8")
    arguments = [
        "--workspace",
        str(workspace),
        "--binary-crate",
        "w-cli",
        "--floor",
        str(floor),
        "--readme",
        str(readme),
    ]
    assert wiring_census.main(arguments) == 1
    assert "::error::README status table does not show" in capsys.readouterr().out

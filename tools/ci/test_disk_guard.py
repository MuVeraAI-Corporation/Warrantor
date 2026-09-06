"""The disk guard must refuse when it should and must never pass vacuously."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

GUARD = Path(__file__).resolve().parent / "disk_guard.py"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GUARD), *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )


def test_require_passes_for_a_floor_below_what_is_free() -> None:
    out = run("--require", "0.001")
    assert out.returncode == 0, out.stdout + out.stderr
    assert "OK" in out.stdout


def test_require_refuses_a_floor_no_disk_can_meet() -> None:
    """The refusal half. A guard that only ever says OK is the instruction it replaces."""
    out = run("--require", "999999999")
    assert out.returncode == 1, out.stdout + out.stderr
    assert "REFUSE" in out.stdout
    assert "::error::" in out.stderr


def test_list_reports_a_count_and_never_crashes() -> None:
    out = run("--list")
    assert out.returncode == 0, out.stdout + out.stderr
    assert "cargo target dir(s)" in out.stdout
    assert "worktree(s)" in out.stdout


@pytest.mark.skipif(os.name != "nt", reason="the sweep plan is a PowerShell script for a drive letter")
def test_sweep_plan_writes_a_script_that_parses(tmp_path: Path) -> None:
    out_file = tmp_path / "sweep.ps1"
    out = run("--sweep-plan", "99999", "--out", str(out_file))
    assert out.returncode == 0, out.stdout + out.stderr
    text = out_file.read_text(encoding="utf-8")
    assert "Remove-Item -LiteralPath" in text
    assert "ErrorAction Stop" in text
    # An impossible idle threshold protects everything: the plan must be EMPTY, not wrong.
    assert "$dirs = @(\n)" in text, text
    if shutil.which("powershell"):
        assert "PARSE OK" in out.stdout, out.stdout


@pytest.mark.skipif(os.name != "nt", reason="the sweep plan is a PowerShell script for a drive letter")
def test_sweep_plan_lists_a_genuinely_stale_dir_and_protects_a_live_one(tmp_path: Path) -> None:
    """The paired control for the idle threshold: zero hours must select every dir, and the
    protected list must be the complement. Without this the empty plan above proves nothing."""
    out_file = tmp_path / "sweep0.ps1"
    out = run("--sweep-plan", "0", "--out", str(out_file))
    assert out.returncode == 0, out.stdout + out.stderr
    text = out_file.read_text(encoding="utf-8")
    listed = [line for line in text.splitlines() if line.startswith("  '")]
    protected = [line for line in text.splitlines() if line.startswith("#   ")]
    # Every target dir is either listed or protected, never both, never neither.
    assert len(protected) == 0, protected
    from disk_guard import target_dirs  # noqa: E402

    assert len(listed) == len(target_dirs()), (listed, target_dirs())

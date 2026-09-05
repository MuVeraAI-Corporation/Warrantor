"""Tests for the US-English gate. A gate nobody tests is a gate nobody can trust to fail."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

GATE = Path(__file__).resolve().parent / "check_us_english.py"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(GATE), *args],
                          capture_output=True, text=True, encoding="utf-8", errors="replace")


def write(tmp_path: Path, text: str) -> str:
    path = tmp_path / "sample.md"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_a_britishism_is_refused(tmp_path: Path) -> None:
    out = run("--files", write(tmp_path, "The organisation prioritised its defence.\n"))
    assert out.returncode == 1
    assert "organisation" in out.stdout


def test_every_britishism_on_a_line_is_reported(tmp_path: Path) -> None:
    """One finding per run makes a fixer iterate, and each iteration is a CI round trip."""
    out = run("--files", write(tmp_path, "The organisation prioritised its defence.\n"))
    for word in ("organisation", "prioritised", "defence"):
        assert word in out.stdout, f"{word} was not reported"


def test_the_american_forms_pass(tmp_path: Path) -> None:
    """The paired allowed control. Without it, a gate that refuses everything looks correct."""
    out = run("--files", write(tmp_path, "The organization prioritized its defense.\n"))
    assert out.returncode == 0, out.stdout


def test_the_two_documented_false_positives_pass(tmp_path: Path) -> None:
    """`forwards` is a verb and `analyses` is the plural of a noun. Both are correct English."""
    out = run("--files", write(tmp_path, "The proxy forwards the call, and the analyses agree.\n"))
    assert out.returncode == 0, out.stdout


def test_a_proper_noun_keeps_its_spelling(tmp_path: Path) -> None:
    out = run("--files", write(tmp_path, "The World Health Organisation published it.\n"))
    assert out.returncode == 0, out.stdout


def test_a_backtick_span_is_treated_as_code(tmp_path: Path) -> None:
    """A document about spelling has to be able to quote the spellings it rejects."""
    out = run("--files", write(tmp_path, "Reject `honour` and `authorisation` in prose.\n"))
    assert out.returncode == 0, out.stdout


def test_a_missing_file_is_an_error_not_a_pass(tmp_path: Path) -> None:
    out = run("--files", str(tmp_path / "does-not-exist.md"))
    assert out.returncode == 1
    assert "no such file" in out.stderr

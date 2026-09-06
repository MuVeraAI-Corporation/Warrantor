"""Tests for the US-English gate.

Most of these pin behavior that a hand-rolled matcher got WRONG. The first version of the gate
vendored the word list and wrote its own regex over the stems; on ordinary American English it
produced six false positives and missed the one real Britishism. Every case below that asserts a
correct-US word passes is there because that version failed it.
"""
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


def test_the_american_forms_pass(tmp_path: Path) -> None:
    """The paired allowed control: a gate that refuses everything would look correct without it."""
    out = run("--files", write(tmp_path, "The organization prioritized its defense.\n"))
    assert out.returncode == 0, out.stdout


def test_ordinary_american_words_that_share_an_ise_stem_pass(tmp_path: Path) -> None:
    """`specialist`, `analysis`, `organism` and friends are correct in both dialects.

    An `-is` stem may only be followed by a specific suffix set, which is why the canonical matcher
    is vendored whole rather than reimplemented from its word list.
    """
    text = ("The specialist ran an analysis. Two analysts reviewed it.\n"
            "An organism is not the same as an organist.\n"
            "Her specialism is catalysis; the catalyst worked. Paralysis, dialysis, hydrolysis.\n"
            "This synthesis of the analysis gives a diagnosis and a prognosis.\n")
    out = run("--files", write(tmp_path, text))
    assert out.returncode == 0, out.stdout


def test_a_britishism_beside_those_words_is_still_caught(tmp_path: Path) -> None:
    """The false-negative half. A stem match on `organism` must not suppress `organisation`."""
    out = run("--files", write(tmp_path, "An organism is not an organisation. The organist played.\n"))
    assert out.returncode == 1, out.stdout
    assert "organisation" in out.stdout


def test_an_adverbial_tail_is_caught(tmp_path: Path) -> None:
    """`recognisably` once reached a published article; the suffix list exists because of it."""
    out = run("--files", write(tmp_path, "The bound is recognisably weaker.\n"))
    assert out.returncode == 1, out.stdout


def test_a_missing_file_is_an_error_not_a_pass(tmp_path: Path) -> None:
    out = run("--files", str(tmp_path / "does-not-exist.md"))
    assert out.returncode == 1
    assert "no such file" in out.stderr


def test_the_vendored_matcher_is_present() -> None:
    """The gate is a scoper over a vendored matcher; without it there is no rule to apply."""
    assert (GATE.parent / "verify-us-english.mjs").exists()


def test_diff_mode_scans_more_than_zero_files() -> None:
    """The vacuous-pass regression.

    A path bug made every repo-relative path fail its existence check, so diff mode reported `ok`
    while scanning zero files. The summary line's own "0 file(s)" was the only tell, and nothing
    asserted on it.
    """
    out = run("origin/main")
    assert "across 0 file(s)" not in out.stdout, out.stdout
    assert out.returncode in (0, 1), out.stdout
    # Either it found files to scan, or the diff was genuinely empty -- never lines without files.
    if "added line(s)" in out.stdout:
        import re
        match = re.search(r"(\d+) added line\(s\) across (\d+) file\(s\)", out.stdout)
        assert match, out.stdout
        lines_added, files_scanned = int(match.group(1)), int(match.group(2))
        if lines_added:
            assert files_scanned > 0, f"{lines_added} added lines resolved to no files"


def test_the_two_documented_false_positives_pass(tmp_path: Path) -> None:
    """`forwards` and `analyses` are correct American English and must not fail a branch.

    The canonical matcher over-flags both, and the house rule names them as known false positives.
    v1 of this gate filtered them; v2 delegated matching to the canonical script and dropped BOTH the
    filter and this test, so a doc comment reading "the proxy forwards the call" failed the gate on a
    real branch. The filter and the test go back together, because the filter without a test is what
    got removed silently the first time.
    """
    text = ("The proxy forwards the call, and every tool the proxy forwards is a composition.\n"
            "The analyses agree with one another.\n")
    out = run("--files", write(tmp_path, text))
    assert out.returncode == 0, out.stdout


def test_the_false_positive_filter_does_not_swallow_a_real_britishism(tmp_path: Path) -> None:
    """The paired control for the filter itself.

    Filtering by word is a blunt instrument, so prove it removes only the two documented words and
    still refuses a genuine Britishism sitting on the same line as one of them.
    """
    out = run("--files", write(tmp_path, "The proxy forwards it to the organisation.\n"))
    assert out.returncode == 1, out.stdout
    assert "organisation" in out.stdout
    assert "forwards" not in out.stdout, "the documented false positive leaked into the findings"

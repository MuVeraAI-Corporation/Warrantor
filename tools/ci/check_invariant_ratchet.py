#!/usr/bin/env python3
"""Ratchet gate for the invariant attack corpus at rust/warrant/tests/invariants/.

The corpus measures whether the twelve formal invariants in docs/02-architecture.md hold. Its
passing count is a published number, so it needs a floor that only moves one way. This script runs
the corpus, compares the result against tools/ci/invariant-ratchet.json, and fails the build on a
regression.

Two counters, because one is not enough:

* ``passing_floor`` -- the passing count may never fall. Deleting a test or breaking an invariant
  trips this.
* ``ignored_ceiling`` -- the ignored count may never rise. Every ignored test in the corpus is a
  recorded finding, so silencing a failing test by adding ``#[ignore]`` would keep the passing
  count intact while quietly widening the gap. This is the counter that catches it.

An improvement fails too, with a message saying to raise the baseline. A ratchet nobody tightens
stops being one, and tightening it is a one-line commit made by whoever earned it.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = REPOSITORY_ROOT / "tools" / "ci" / "invariant-ratchet.json"
BASELINE_FORMAT = "warrantor.invariant-ratchet/1"

# `cargo test`'s summary line, e.g.
# test result: ok. 65 passed; 0 failed; 19 ignored; 0 measured; 0 filtered out; finished in 0.11s
RESULT_PATTERN = re.compile(
    r"test result: \w+\. (?P<passed>\d+) passed; (?P<failed>\d+) failed; (?P<ignored>\d+) ignored;"
)


@dataclass(frozen=True)
class CorpusResult:
    """What one run of the corpus reported."""

    passed: int
    failed: int
    ignored: int


@dataclass(frozen=True)
class Baseline:
    """The floor and ceiling the corpus must stay inside."""

    passing_floor: int
    ignored_ceiling: int


def load_baseline(path: Path) -> Baseline:
    """Read the ratchet baseline, refusing an unversioned or malformed one."""
    document = json.loads(path.read_text(encoding="utf-8"))
    declared_format = document.get("format")
    if declared_format != BASELINE_FORMAT:
        raise ValueError(f"baseline format is {declared_format!r}, expected {BASELINE_FORMAT!r}")
    return Baseline(
        passing_floor=int(document["passing_floor"]),
        ignored_ceiling=int(document["ignored_ceiling"]),
    )


def parse_result(output: str) -> CorpusResult:
    """Extract the counts from a cargo test run.

    Refuses output with no summary line rather than reporting zeroes: a run that did not happen
    must not read as a run in which nothing failed.
    """
    match = RESULT_PATTERN.search(output)
    if match is None:
        raise ValueError("cargo test produced no `test result:` line; the corpus did not run")
    return CorpusResult(
        passed=int(match.group("passed")),
        failed=int(match.group("failed")),
        ignored=int(match.group("ignored")),
    )


def run_corpus(repository_root: Path) -> tuple[CorpusResult, str]:
    """Run the corpus and return its counts alongside the raw output."""
    # A fixed argument vector with no shell: nothing here interpolates user input.
    completed = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "warrantor-warrant",
            "--test",
            "invariants",
            "-j",
            "2",
        ],
        cwd=repository_root / "rust",
        capture_output=True,
        text=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    return parse_result(output), output


def report_findings(repository_root: Path) -> str:
    """Run the ignored tests and return their output, for the log.

    These are the recorded findings and they fail by design, so the return code is discarded. The
    point is that nobody reading a green build can claim not to have been told.
    """
    # A fixed argument vector with no shell: nothing here interpolates user input.
    completed = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "warrantor-warrant",
            "--test",
            "invariants",
            "-j",
            "2",
            "--",
            "--ignored",
        ],
        cwd=repository_root / "rust",
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout + completed.stderr


def check(result: CorpusResult, baseline: Baseline) -> list[str]:
    """Return the reasons this run fails the ratchet, empty if it passes."""
    problems: list[str] = []

    if result.failed:
        problems.append(
            f"{result.failed} corpus test(s) failed. A failing invariant test is a finding: record "
            f"it in docs/W1-delivery-gaps.md and mark it #[ignore] with the invariant, the fixing "
            f"task and the date. Never weaken the assertion."
        )
    if result.passed < baseline.passing_floor:
        problems.append(
            f"the passing count fell from {baseline.passing_floor} to {result.passed}. The corpus "
            f"guarantee set may only tighten."
        )
    if result.ignored > baseline.ignored_ceiling:
        problems.append(
            f"the ignored count rose from {baseline.ignored_ceiling} to {result.ignored}. Every "
            f"ignored test is an unfixed invariant violation, so this is a widening gap even "
            f"though the passing count held."
        )
    if result.passed > baseline.passing_floor or result.ignored < baseline.ignored_ceiling:
        problems.append(
            f"the corpus improved ({result.passed} passing, {result.ignored} ignored) and "
            f"{BASELINE_PATH.relative_to(REPOSITORY_ROOT)} still says "
            f"{baseline.passing_floor}/{baseline.ignored_ceiling}. Raise the ratchet in the same "
            f"commit, or the floor stops tracking reality."
        )
    return problems


def main() -> int:
    """Run the corpus and enforce the ratchet. Returns a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--show-findings",
        action="store_true",
        help="also run the ignored tests and print their failures, which are the recorded findings",
    )
    arguments = parser.parse_args()

    baseline = load_baseline(BASELINE_PATH)
    result, output = run_corpus(REPOSITORY_ROOT)
    print(output)

    if arguments.show_findings:
        print("=" * 80)
        print("Recorded findings -- these fail by design. Each names its invariant and its task.")
        print("=" * 80)
        print(report_findings(REPOSITORY_ROOT))

    problems = check(result, baseline)
    if problems:
        print("invariant ratchet: FAILED", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(
        f"invariant ratchet: ok ({result.passed} passing at floor {baseline.passing_floor}, "
        f"{result.ignored} recorded findings at ceiling {baseline.ignored_ceiling})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

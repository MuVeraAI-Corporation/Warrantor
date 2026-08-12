#!/usr/bin/env python3
"""Run a required check against every Go module in the Warrantor monorepo."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
GO_ROOT = REPOSITORY_ROOT / "go"
SUPPORTED_CHECKS = ("test", "vet")


@dataclass(frozen=True)
class ModuleResult:
    """Result of one check for one Go module."""

    module: str
    check: str
    passed: bool
    duration_ms: int
    detail: str


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("check", choices=SUPPORTED_CHECKS)
    parser.add_argument("--report", type=Path, help="Optional JSON report path")
    return parser.parse_args()


def discover_modules() -> list[Path]:
    """Discover every Go module below the repository's Go root."""

    modules = sorted(path.parent for path in GO_ROOT.glob("*/go.mod"))
    if not modules:
        raise RuntimeError(f"no Go modules found below {GO_ROOT}")
    return modules


def check_module(module: Path, check: str, go_executable: str) -> ModuleResult:
    """Run a Go check with a hermetic temporary build cache."""

    environment = os.environ.copy()
    environment["GOCACHE"] = str(Path(tempfile.gettempdir()) / "aumos-go-build")
    command = [go_executable, check, "./..."]
    started = datetime.now(UTC)
    completed = subprocess.run(
        command,
        cwd=module,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    output = (completed.stdout + completed.stderr).strip()
    detail = output if output else f"exit code {completed.returncode}"
    return ModuleResult(
        module=module.name,
        check=check,
        passed=completed.returncode == 0,
        duration_ms=duration_ms,
        detail=detail,
    )


def write_report(path: Path, check: str, results: list[ModuleResult]) -> None:
    """Write a machine-readable check report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "language": "go",
        "check": check,
        "module_count": len(results),
        "passed": all(result.passed for result in results),
        "results": [asdict(result) for result in results],
    }
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    """Run the selected check against every discovered Go module."""

    arguments = parse_arguments()
    go_executable = shutil.which("go")
    if go_executable is None:
        print("go checks: required 'go' executable is unavailable")
        return 2
    try:
        modules = discover_modules()
        results = [
            check_module(module, arguments.check, go_executable) for module in modules
        ]
    except RuntimeError as error:
        print(f"go checks: {error}")
        return 2

    for result in results:
        marker = "ok" if result.passed else "FAIL"
        print(f"[{marker:4}] {result.module} ({result.duration_ms}ms)")
        if not result.passed:
            print(result.detail)

    passed_count = sum(result.passed for result in results)
    print(
        f"RESULT: {'PASS' if passed_count == len(results) else 'FAIL'} — "
        f"{passed_count}/{len(results)} Go modules passed {arguments.check}"
    )
    if arguments.report is not None:
        write_report(arguments.report, arguments.check, results)
        print(f"evidence: {arguments.report}")
    return 0 if passed_count == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run a required check against every Python project in the AumOS monorepo."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PYTHON_ROOT = REPOSITORY_ROOT / "python"
SUPPORTED_CHECKS = ("test", "lint", "format")


@dataclass(frozen=True)
class ProjectResult:
    """Result of one check for one Python project."""

    project: str
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


def discover_projects() -> list[Path]:
    """Discover every testable src-layout Python project."""

    projects = sorted(path.parent for path in PYTHON_ROOT.glob("*/pyproject.toml"))
    if not projects:
        raise RuntimeError(f"no Python projects found below {PYTHON_ROOT}")
    invalid = [project for project in projects if not (project / "src").is_dir()]
    if invalid:
        names = ", ".join(project.name for project in invalid)
        raise RuntimeError(f"Python projects missing src directories: {names}")
    return projects


def command_for(project: Path, check: str) -> list[str]:
    """Build the command for a project check."""

    if check == "test":
        if not (project / "tests").is_dir():
            raise RuntimeError(f"{project.name}: required tests directory is missing")
        return [sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"]
    targets = ["src"]
    if (project / "tests").is_dir():
        targets.append("tests")
    if check == "lint":
        return [sys.executable, "-m", "ruff", "check", *targets]
    return [sys.executable, "-m", "ruff", "format", "--check", *targets]


def execute_project_command(
    project: Path,
    check: str,
    command: list[str],
    environment: dict[str, str],
) -> ProjectResult:
    """Execute one prepared project command and normalize its result."""

    started = datetime.now(UTC)
    completed = subprocess.run(
        command,
        cwd=project,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    output = (completed.stdout + completed.stderr).strip()
    detail = output if output else f"exit code {completed.returncode}"
    return ProjectResult(
        project=project.name,
        check=check,
        passed=completed.returncode == 0,
        duration_ms=duration_ms,
        detail=detail,
    )


def check_project(project: Path, check: str) -> ProjectResult:
    """Run a check in an isolated project import and temporary-file environment."""

    command = command_for(project, check)
    environment = os.environ.copy()
    loopback_hosts = ("localhost", "127.0.0.1", "::1")
    configured_no_proxy = environment.get("NO_PROXY") or environment.get(
        "no_proxy", ""
    )
    no_proxy_hosts = [
        host.strip() for host in configured_no_proxy.split(",") if host.strip()
    ]
    for loopback_host in loopback_hosts:
        if loopback_host not in no_proxy_hosts:
            no_proxy_hosts.append(loopback_host)
    normalized_no_proxy = ",".join(no_proxy_hosts)
    environment["NO_PROXY"] = normalized_no_proxy
    environment["no_proxy"] = normalized_no_proxy
    source_path = str(project / "src")
    existing_python_path = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        source_path
        if not existing_python_path
        else source_path + os.pathsep + existing_python_path
    )
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    if check != "test":
        return execute_project_command(project, check, command, environment)

    with tempfile.TemporaryDirectory(
        prefix=f"aumos-pytest-{project.name}-"
    ) as base_temp:
        command.extend(["--basetemp", base_temp])
        return execute_project_command(project, check, command, environment)


def write_report(path: Path, check: str, results: list[ProjectResult]) -> None:
    """Write a machine-readable check report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "language": "python",
        "check": check,
        "project_count": len(results),
        "passed": all(result.passed for result in results),
        "results": [asdict(result) for result in results],
    }
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    """Run the selected check against every discovered project."""

    arguments = parse_arguments()
    try:
        projects = discover_projects()
        results = [check_project(project, arguments.check) for project in projects]
    except RuntimeError as error:
        print(f"python checks: {error}", file=sys.stderr)
        return 2

    for result in results:
        marker = "ok" if result.passed else "FAIL"
        print(f"[{marker:4}] {result.project} ({result.duration_ms}ms)")
        if not result.passed:
            print(result.detail)

    passed_count = sum(result.passed for result in results)
    print(
        f"RESULT: {'PASS' if passed_count == len(results) else 'FAIL'} — "
        f"{passed_count}/{len(results)} Python projects passed {arguments.check}"
    )
    if arguments.report is not None:
        write_report(arguments.report, arguments.check, results)
        print(f"evidence: {arguments.report}")
    return 0 if passed_count == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())

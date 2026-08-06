"""``agentsec-lab`` CLI entrypoint.

Usage:
    agentsec-lab run --target-refusing         # safe baseline (0 findings)
    agentsec-lab run --target-compliant        # unsafe baseline (findings)
    agentsec-lab run --target-script ./my-agent.sh
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from agentsec_lab import CompliantTarget, RefusingTarget, Target, default_lab


class ScriptTarget:
    """A target backed by an external script that takes a prompt on stdin and prints a response."""

    def __init__(self, script: str) -> None:
        self.script = script

    def respond(self, prompt: str) -> str:
        try:
            result = subprocess.run(
                [self.script],
                input=prompt,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return result.stdout.strip()
        except (subprocess.SubprocessError, OSError) as e:
            return f"<script-target error: {e}>"


def _make_target(args: argparse.Namespace) -> Target:
    if args.target_refusing:
        return RefusingTarget()
    if args.target_compliant:
        return CompliantTarget()
    if args.target_script:
        if not os.path.exists(args.target_script):
            print(f"agentsec-lab: script not found: {args.target_script}", file=sys.stderr)
            sys.exit(2)
        return ScriptTarget(args.target_script)
    print("agentsec-lab: must specify a target (try --help)", file=sys.stderr)
    sys.exit(2)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agentsec-lab", description="Run adversarial agent scenarios against a target.")
    sub = p.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="Run scenarios against a target.")
    tgt = run_p.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--target-refusing", action="store_true", help="Use the safe baseline target (always refuses).")
    tgt.add_argument("--target-compliant", action="store_true", help="Use the unsafe baseline target (always complies).")
    tgt.add_argument("--target-script", metavar="PATH", help="External script target (reads prompt on stdin, prints response).")
    run_p.add_argument("--holdouts", default=None, metavar="PATH",
                       help="JSON file of private holdout scenarios to include.")
    run_p.add_argument("--include-hidden", action="store_true",
                       help="Include hidden holdouts (default: public scenarios only).")

    list_p = sub.add_parser("list", help="List registered scenarios.")
    list_p.add_argument("--include-hidden", action="store_true")

    args = p.parse_args(argv)

    lab = default_lab()
    if args.cmd == "list":
        # Iterate the registry directly (no run).
        for scen_id, scen in lab._scenarios.items():  # noqa: SLF001
            if not args.include_hidden and scen.hidden:
                continue
            print(f"{scen_id}\t{scen.category.value}\t{scen.severity.value}\t{'hidden' if scen.hidden else 'public'}")
        return 0

    if args.cmd == "run":
        if args.holdouts:
            n = lab.load_holdouts(args.holdouts)
            print(f"agentsec-lab: loaded {n} holdout scenario(s) from {args.holdouts}", file=sys.stderr)
        target = _make_target(args)
        result = lab.run(target, target_name=_target_label(args), only_public=not args.include_hidden)
        print(json.dumps({
            "run_id": result.run_id,
            "target": result.target_name,
            "started_at": result.started_at,
            "scenarios_run": len(result.findings),
            "detected": result.detected_count,
            "critical_or_high_findings": len(result.critical_or_high),
            "findings": [
                {
                    "scenario_id": f.scenario_id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "detected": f.detected,
                }
                for f in result.findings
            ],
        }, indent=2))
        if result.critical_or_high:
            print(
                f"agentsec-lab: {len(result.critical_or_high)} high/critical finding(s) must be filed "
                f"per docs/cross-cutting/14-security-disclosure-policy.md before public release.",
                file=sys.stderr,
            )
        return 0

    return 2


def _target_label(args: argparse.Namespace) -> str:
    if args.target_refusing:
        return "refusing-baseline"
    if args.target_compliant:
        return "compliant-baseline"
    return f"script:{os.path.basename(args.target_script)}"


if __name__ == "__main__":
    sys.exit(main())

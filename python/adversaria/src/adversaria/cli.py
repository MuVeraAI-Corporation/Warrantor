"""``adversaria`` CLI — run the default attack suite against a built-in baseline target."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

from adversaria import (
    AttackSuite,
    AttackType,
    CompliantTarget,
    RefusingTarget,
    Target,
    default_suite,
)


class ScriptTarget:
    """A target backed by an external script (reads prompt on stdin, prints response)."""

    def __init__(self, script: str) -> None:
        self.script = script

    def respond(self, prompt: str) -> str:
        try:
            r = subprocess.run(
                [self.script], input=prompt, capture_output=True, text=True, timeout=30, check=False
            )
            return r.stdout.strip()
        except (subprocess.SubprocessError, OSError) as e:
            return f"<script-target error: {e}>"


def _make_target(args: argparse.Namespace) -> Target:
    if args.target_refusing:
        return RefusingTarget()
    if args.target_compliant:
        return CompliantTarget()
    if args.target_script:
        if not os.path.exists(args.target_script):
            print(f"adversaria: script not found: {args.target_script}", file=sys.stderr)
            sys.exit(2)
        return ScriptTarget(args.target_script)
    print("adversaria: must specify a target (try --help)", file=sys.stderr)
    sys.exit(2)


def _build_suite(args: argparse.Namespace) -> AttackSuite:
    suite = AttackSuite()
    if args.attacks:
        for name in args.attacks:
            try:
                suite.add(AttackType(name), args.count)
            except ValueError:
                print(f"adversaria: unknown attack type {name!r}", file=sys.stderr)
                sys.exit(2)
        return suite
    return default_suite()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="adversaria", description="Run adversarial attacks against a target."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="Run attacks against a target.")
    tgt = run_p.add_mutually_exclusive_group(required=True)
    tgt.add_argument(
        "--target-refusing", action="store_true", help="Safe baseline (always refuses)."
    )
    tgt.add_argument(
        "--target-compliant", action="store_true", help="Unsafe baseline (always complies)."
    )
    tgt.add_argument("--target-script", metavar="PATH", help="External script target.")
    run_p.add_argument(
        "--attacks", nargs="+", help="Attack types to run (default: all 5 built-in types)."
    )
    run_p.add_argument("--count", type=int, default=1, help="Prompts per attack type (default 1).")

    list_p = sub.add_parser("list", help="List available attack types.")
    _ = list_p  # no extra args

    args = p.parse_args(argv)

    if args.cmd == "list":
        for at in AttackType:
            if at is AttackType.CUSTOM:
                continue
            print(at.value)
        return 0

    # cmd == "run"
    suite = _build_suite(args)
    target = _make_target(args)
    summary = suite.run(target)
    out = {
        "run_id": summary.run_id,
        "started_at": summary.started_at,
        "attack_count": summary.attack_count,
        "success_count": summary.success_count,
        "success_rate": summary.success_rate,
        "critical_or_high": len(summary.critical_or_high),
        "results": [
            {
                "id": r.prompt.id,
                "type": r.prompt.attack_type.value,
                "succeeded": r.succeeded,
                "severity": r.severity.value,
            }
            for r in summary.results
        ],
    }
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    if summary.critical_or_high:
        print(
            f"adversaria: {len(summary.critical_or_high)} critical/high successful attack(s) — "
            f"file per docs/cross-cutting/14-security-disclosure-policy.md",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())

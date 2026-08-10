"""``warrantor-agent`` command-line entry point.

A small CLI that exposes the SDK's status and a couple of handy one-shot operations so an
operator can sanity-check the wiring without writing Python. The SDK itself is the primary
surface; this module just makes it reachable from a shell.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import AumOS, __version__


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="warrantor-agent",
        description="AumOS Agent SDK — security primitives for coding agents.",
    )
    p.add_argument("--version", action="version", version=f"warrantor-agent {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Print SDK status (mode, config, version).")

    sp = sub.add_parser("scan-secrets", help="Scan stdin or a --text argument for secrets.")
    sp.add_argument("--text", help="Text to scan. If omitted, reads from stdin.")
    sp.add_argument("--mode", default="standalone", choices=("standalone", "connected"))

    ip = sub.add_parser("issue", help="Issue a mock agent identity for a subject.")
    ip.add_argument("subject", help="SPIFFE ID of the agent to issue.")
    ip.add_argument("--mode", default="standalone", choices=("standalone", "connected"))

    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "status":
        agent = AumOS(mode="standalone")
        cfg = agent.config.resolved()
        print(
            json.dumps(
                {
                    "version": __version__,
                    "mode": agent.mode,
                    "agent_svid": agent.config.agent_svid,
                    "endpoints": {
                        k: cfg[k]
                        for k in (
                            "agent_identity_url",
                            "flight_recorder_url",
                            "kill_switch_url",
                            "credential_vault_url",
                            "eval_guard_url",
                        )
                    },
                    "evidence_count": len(agent.evidence),
                },
                indent=2,
            )
        )
        return 0

    if args.cmd == "scan-secrets":
        text = args.text if args.text is not None else sys.stdin.read()
        agent = AumOS(mode=args.mode)
        findings = agent.scan_secrets(text)
        print(
            json.dumps(
                {"count": len(findings), "findings": [f.as_dict() for f in findings]}, indent=2
            )
        )
        return 0

    if args.cmd == "issue":
        agent = AumOS(mode=args.mode)
        print(json.dumps(agent.issue_identity(args.subject), indent=2))
        return 0

    return 2  # unreachable: argparse enforces required subcommand


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""warrantor-harness CLI."""

from __future__ import annotations

import argparse
import json
import sys

from warrantor_harness import AgentType, HarnessConfig, SideEffectClass, secure_session


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="warrantor-harness", description="Run a coding agent in a secured Warrantor session."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="Run a command in a secured session.")
    run_p.add_argument(
        "--agent", choices=[a.value for a in AgentType], default=AgentType.GENERIC.value
    )
    run_p.add_argument("--dir", default=".", help="Working directory.")
    run_p.add_argument(
        "--tools", default="git,npm,cargo,python,go,make", help="Comma-separated allowed tools."
    )
    run_p.add_argument(
        "--side-effect",
        choices=[s.value for s in SideEffectClass],
        default=SideEffectClass.WRITE.value,
    )
    run_p.add_argument(
        "--no-kill-on-secret", action="store_true", help="Don't kill on secret exposure."
    )
    run_p.add_argument("--timeout", type=int, default=3600, help="Max session duration (seconds).")
    run_p.add_argument("command", help="The command to run.")

    cfg_p = sub.add_parser("config", help="Generate agent-specific config files.")
    cfg_p.add_argument("--agent", choices=["claude_code", "codex", "cursor"], required=True)
    cfg_p.add_argument("--dir", default=".", help="Working directory.")

    args = p.parse_args(argv)

    if args.cmd == "config":
        _generate_config(args)
        return 0

    if args.cmd == "run":
        config = HarnessConfig(
            agent_type=AgentType(args.agent),
            working_dir=args.dir,
            allowed_tools=args.tools.split(","),
            side_effect_class=SideEffectClass(args.side_effect),
            kill_on_secret_exposure=not args.no_kill_on_secret,
            max_duration_seconds=args.timeout,
        )
        with secure_session(config) as session:
            result = session.run_agent(args.command)
        summary = session.result.to_dict()
        summary["last_command_result"] = {
            "exit_code": result.get("exit_code", -1),
            "secrets_found": result.get("secrets_found", []),
        }
        json.dump(summary, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0 if summary["status"] == "completed" else 1

    return 2


def _generate_config(args: argparse.Namespace) -> None:
    """Generate agent-specific config files."""
    import os

    d = args.dir
    if args.agent == "claude_code":
        path = os.path.join(d, "CLAUDE.md")
        content = """# CLAUDE.md — Warrantor Secured Agent

## Allowed Tools
git, npm, cargo, python, go, make

## Security Rules
- Every action is recorded as an Agent Action Receipt (P2 AAR)
- Secret exposure triggers kill-switch (invariant I-09)
- File access is tracked and logged
- Side-effect class: write

## Warrantor Integration
This project uses Warrantor security infrastructure:
- pip install warrantor-agent
- npx @warrantor/mcp-server
"""
    elif args.agent == "codex":
        path = os.path.join(d, "AGENTS.md")
        content = """# AGENTS.md — Warrantor Secured Agent

## Tools
git, npm, cargo, python, go, make

## Security
- All actions recorded via Warrantor flight-recorder (E1)
- Credential scanning via credential-vault (R4)
- Kill-switch armed (R3)

## Warrantor
pip install warrantor-agent
"""
    else:  # cursor
        path = os.path.join(d, ".cursorrules")
        content = """# .cursorrules — Warrantor Secured Agent

You are operating in an Warrantor-secured session.
- Every action is tracked and recorded
- Secrets in output will trigger kill-switch
- Use Warrantor MCP tools for signing, identity, evidence

Allowed tools: git, npm, cargo, python, go, make
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Generated {path}")


if __name__ == "__main__":
    sys.exit(main())

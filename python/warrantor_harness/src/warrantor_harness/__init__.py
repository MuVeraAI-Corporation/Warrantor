"""Warrantor Harness — secure coding agent wrappers.

Wraps coding agent sessions (Claude Code, OpenAI Codex, Cursor) with Warrantor security:
  1. eval-guard pre-flight sandbox boundary checks (R2)
  2. Every file/command the agent touches is tracked
  3. Every significant action recorded as an AAR (E1, invariant I-07)
  4. Credentials in agent output scanned (R4)
  5. On misbehavior, kill-switch can terminate (R3, invariant I-09)
"""

from __future__ import annotations

import os
import re
import shlex
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from ._lifetime import ProcessSupervisor


class AgentType(str, Enum):
    """Supported coding agent types."""

    CLAUDE_CODE = "claude_code"
    CODEX = "codex"
    CURSOR = "cursor"
    GENERIC = "generic"


class SideEffectClass(str, Enum):
    """Side-effect severity for the session."""

    READ = "read"
    WRITE = "write"
    FINANCIAL = "financial"
    DESTRUCTIVE = "destructive"
    PHYSICAL = "physical"


class SessionStatus(str, Enum):
    """Session lifecycle status."""

    ACTIVE = "active"
    COMPLETED = "completed"
    KILLED = "killed"
    ERROR = "error"


@dataclass
class HarnessConfig:
    """Configuration for a secured agent session."""

    agent_type: AgentType = AgentType.GENERIC
    working_dir: str = "."
    allowed_tools: list[str] = field(
        default_factory=lambda: ["git", "npm", "cargo", "python", "go", "make"]
    )
    side_effect_class: SideEffectClass = SideEffectClass.WRITE
    require_attestation: bool = False
    kill_on_secret_exposure: bool = True
    max_duration_seconds: int = 3600


@dataclass
class FileAccess:
    """A tracked file access by the agent."""

    path: str
    mode: str  # "read" or "write"
    timestamp: str = ""


@dataclass
class ActionRecord:
    """One agent action recorded as a receipt."""

    action_id: str
    tool: str
    command: str
    outcome: str  # "committed", "failed", "killed"
    timestamp: str = ""
    secret_findings: list[str] = field(default_factory=list)


@dataclass
class SessionResult:
    """Summary of a completed agent session."""

    session_id: str
    agent_type: AgentType
    status: SessionStatus
    started_at: str
    ended_at: str = ""
    action_count: int = 0
    file_accesses: list[FileAccess] = field(default_factory=list)
    actions: list[ActionRecord] = field(default_factory=list)
    receipts: list[dict[str, Any]] = field(default_factory=list)
    secrets_found: int = 0
    kill_reason: str = ""
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "agent_type": self.agent_type.value,
            "status": self.status.value,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "action_count": self.action_count,
            "file_accesses": len(self.file_accesses),
            "receipts": len(self.receipts),
            "secrets_found": self.secrets_found,
            "kill_reason": self.kill_reason,
            "duration_seconds": round(self.duration_seconds, 2),
        }


# Secret patterns (same as R4 credential-vault)
_SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("GitHub PAT", re.compile(r"ghp_[0-9A-Za-z]{36}")),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{48}")),
    ("GitLab PAT", re.compile(r"glpat-[0-9A-Za-z_-]{20}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
]


def _scan_secrets(text: str) -> list[str]:
    """Scan text for exposed credentials. Returns list of type descriptions."""
    findings: list[str] = []
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(name)
    return findings


def _utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _split_command(command: str) -> list[str]:
    """Split a command string into argv, correctly on both POSIX and Windows.

    `shlex` defaults to POSIX rules, where a backslash is an escape character. On Windows
    that silently destroys any absolute path -- ``C:\\Python\\python.exe`` parses as
    ``C:Pythonpython.exe`` -- so a legitimate command gets refused by the allowlist for a
    reason that has nothing to do with policy. Non-POSIX mode keeps backslashes but leaves
    quotes attached to the tokens, which then have to be stripped.
    """

    posix = os.name != "nt"
    try:
        argv = shlex.split(command, posix=posix)
    except ValueError:
        return []  # unbalanced quotes: unparseable, therefore not runnable
    if not posix:
        argv = [
            token[1:-1]
            if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'"
            else token
            for token in argv
        ]
    return argv


class TrackedSession:
    """A tracked coding agent session with Warrantor security controls."""

    def __init__(self, config: HarnessConfig) -> None:
        self.config = config
        self.session_id = str(uuid.uuid4())
        self.started_at = _utcnow()
        self.status = SessionStatus.ACTIVE
        self.result = SessionResult(
            session_id=self.session_id,
            agent_type=config.agent_type,
            status=SessionStatus.ACTIVE,
            started_at=self.started_at,
        )
        self._start_time = time.monotonic()
        self._killed = False
        # W0: OS-enforced lifetime linkage. Without it a command spawned here outlives the
        # harness -- unsupervised, unbounded, with nothing scanning its output. See _lifetime.
        self._supervisor = ProcessSupervisor().__enter__()
        self.lifetime_linkage = self._supervisor.linkage

    def _resolve_argv(self, command: str) -> list[str] | None:
        """Parse ``command`` into argv, or return None if it is not allowed (AX-30).

        The previous implementation was bypassable three separate ways, and each one alone
        was sufficient:

        * it took ``command.split()[0]`` -- only the FIRST token -- then ran the whole string
          with ``shell=True``. ``git; rm -rf /`` was approved as ``git`` and executed entire.
        * it matched with ``endswith``, so ``evilgit`` satisfied an allowlist of ``git``.
        * ``shell=True`` gave every command a shell, so ``;``, ``&&``, ``|``, backticks and
          ``$()`` were all live.

        Now: parse to real argv with shlex, match the basename EXACTLY, and execute with
        ``shell=False``. Shell metacharacters stop being operators and become ordinary
        argument text, so the allowlist is the only way through.
        """

        argv = _split_command(command)
        if not argv:
            return None
        # Deliberately NO shell-metacharacter filter. `shell=False` already makes `;`, `&&`
        # and `$(...)` inert -- they arrive as literal argument text -- so a filter would add
        # no security while rejecting legitimate input: `git commit -m 'fix: a; b'` carries a
        # semicolon inside a quoted message, and `python -c 'import time; time.sleep(1)'`
        # carries one by necessity. A rule that blocks real commands to re-block something
        # already blocked trains people to disable it.
        base = os.path.basename(argv[0])
        if base not in set(self.config.allowed_tools):
            return None
        return argv

    def _check_tool_allowed(self, command: str) -> bool:
        """Whether ``command`` names an allowed tool. Retained for callers and tests."""
        return self._resolve_argv(command) is not None

    def _emit_receipt(
        self, tool: str, command: str, outcome: str, secrets: list[str] | None = None
    ) -> dict[str, Any]:
        """Emit an Agent Action Receipt (P2 AAR) for this action."""
        receipt = {
            "id": f"aar-{uuid.uuid4()}",
            "session_id": self.session_id,
            "actor": f"agent:{self.config.agent_type.value}",
            "tool": tool,
            "command": command[:200],  # truncate long commands
            "outcome": outcome,
            "side_effect_class": self.config.side_effect_class.value,
            "emitted_at": _utcnow(),
            "secret_findings": secrets or [],
        }
        self.result.receipts.append(receipt)
        self.result.actions.append(
            ActionRecord(
                action_id=receipt["id"],
                tool=tool,
                command=command[:200],
                outcome=outcome,
                timestamp=receipt["emitted_at"],
                secret_findings=secrets or [],
            )
        )
        self.result.action_count += 1
        return receipt

    def track_file_access(self, path: str, mode: str) -> None:
        """Record a file access by the agent."""
        self.result.file_accesses.append(FileAccess(path=path, mode=mode, timestamp=_utcnow()))

    def scan_output(self, text: str) -> list[str]:
        """Scan agent output for exposed secrets. Returns list of finding descriptions."""
        return _scan_secrets(text)

    def run_agent(self, command: str, timeout: int | None = None) -> dict[str, Any]:
        """Run a command in the tracked environment.

        Returns a result dict with stdout, stderr, exit_code, secrets_found, receipt.
        """
        if self._killed:
            return {"error": "session killed", "exit_code": -1}

        # Check tool allowlist. argv is the parsed command; None means "refuse".
        argv = self._resolve_argv(command)
        if argv is None:
            receipt = self._emit_receipt(
                tool=command.split()[0] if command else "unknown",
                command=command,
                outcome="failed",
            )
            return {
                "error": f"tool not allowed (allowed: {self.config.allowed_tools})",
                "exit_code": -1,
                "receipt": receipt,
            }

        # Run the command. shell=False and an argv LIST, never the raw string: with a shell
        # the allowlist only ever gated the first token while the rest of the line ran
        # unchecked (AX-30).
        try:
            effective_timeout = timeout or self.config.max_duration_seconds
            # Supervised: the whole process TREE is bounded by the deadline, and the tree is
            # lifetime-linked to this harness. A plain subprocess.run bounded only the direct
            # child, so anything the command forked survived both the timeout and the harness.
            proc = self._supervisor.run(
                argv,
                cwd=self.config.working_dir,
                timeout=effective_timeout,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            exit_code = proc.returncode
            outcome = "failed" if (proc.timed_out or exit_code != 0) else "committed"
        except Exception as e:
            stdout = ""
            stderr = str(e)
            exit_code = -1
            outcome = "failed"

        # Scan output for secrets
        secrets = self.scan_output(stdout + stderr)
        if secrets:
            self.result.secrets_found += len(secrets)
            if self.config.kill_on_secret_exposure:
                self.kill(f"secret exposure detected: {', '.join(secrets)}")
                outcome = "killed"

        receipt = self._emit_receipt(
            tool=command.split()[0] if command else "unknown",
            command=command,
            outcome=outcome,
            secrets=secrets,
        )

        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "secrets_found": secrets,
            "receipt": receipt,
        }

    def kill(self, reason: str) -> None:
        """Trigger the kill-switch and terminate the session (invariant I-09)."""
        if not self._killed:
            self._killed = True
            self.status = SessionStatus.KILLED
            self.result.status = SessionStatus.KILLED
            self.result.kill_reason = reason
            # Stop the agent, do not merely record that we decided to. Before this, kill() set
            # a flag that was checked on the NEXT run_agent call -- so a long-running command
            # already in flight kept going after a secret was detected in its own output.
            self._supervisor.terminate_all()
            self._emit_receipt(tool="kill_switch", command=f"kill: {reason}", outcome="killed")

    def close(self) -> SessionResult:
        """Close the session and return the summary."""
        if not self._killed and self.status == SessionStatus.ACTIVE:
            self.status = SessionStatus.COMPLETED
            self.result.status = SessionStatus.COMPLETED
        self.result.ended_at = _utcnow()
        self.result.duration_seconds = time.monotonic() - self._start_time
        # Releases the job object on Windows, killing anything still in it.
        self._supervisor.__exit__(None, None, None)
        return self.result


@contextmanager
def secure_session(config: HarnessConfig):
    """Context manager that wraps a coding agent session with Warrantor security.

    Usage:
        with secure_session(config) as session:
            result = session.run_agent("claude --print 'hello'")
    """
    session = TrackedSession(config)
    try:
        yield session
    except Exception as e:
        session.kill(f"exception: {e}")
        raise
    finally:
        session.close()


def parse_claude_code_config(working_dir: str) -> HarnessConfig:
    """Parse CLAUDE.md to configure the harness for Claude Code."""
    config = HarnessConfig(agent_type=AgentType.CLAUDE_CODE, working_dir=working_dir)
    claude_md = os.path.join(working_dir, "CLAUDE.md")
    if os.path.exists(claude_md):
        with open(claude_md, encoding="utf-8") as claude_file:
            content = claude_file.read()
        # Parse allowed tools from CLAUDE.md if specified
        for line in content.split("\n"):
            if "allowed tools" in line.lower() or "tools:" in line.lower():
                # Simple parsing — extract tool names
                parts = line.split(":", 1)
                if len(parts) > 1:
                    tools = [t.strip() for t in parts[1].split(",") if t.strip()]
                    if tools:
                        config.allowed_tools = tools
    return config


def parse_codex_config(working_dir: str) -> HarnessConfig:
    """Parse AGENTS.md to configure the harness for OpenAI Codex."""
    config = HarnessConfig(agent_type=AgentType.CODEX, working_dir=working_dir)
    agents_md = os.path.join(working_dir, "AGENTS.md")
    if os.path.exists(agents_md):
        with open(agents_md, encoding="utf-8") as agents_file:
            content = agents_file.read()
        for line in content.split("\n"):
            if "tools" in line.lower() and ":" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    tools = [t.strip() for t in parts[1].split(",") if t.strip()]
                    if tools:
                        config.allowed_tools = tools
    return config


def parse_cursor_config(working_dir: str) -> HarnessConfig:
    """Parse .cursorrules to configure the harness for Cursor."""
    config = HarnessConfig(agent_type=AgentType.CURSOR, working_dir=working_dir)
    cursorrules = os.path.join(working_dir, ".cursorrules")
    if os.path.exists(cursorrules):
        config.require_attestation = True  # Cursor sessions tend to be more autonomous
    return config


__all__ = [
    "ActionRecord",
    "AgentType",
    "FileAccess",
    "HarnessConfig",
    "SessionResult",
    "SessionStatus",
    "SideEffectClass",
    "TrackedSession",
    "parse_claude_code_config",
    "parse_codex_config",
    "parse_cursor_config",
    "secure_session",
]

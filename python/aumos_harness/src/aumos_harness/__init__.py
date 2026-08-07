"""AumOS Harness — secure coding agent wrappers.

Wraps coding agent sessions (Claude Code, OpenAI Codex, Cursor) with AumOS security:
  1. eval-guard pre-flight sandbox boundary checks (R2)
  2. Every file/command the agent touches is tracked
  3. Every significant action recorded as an AAR (E1, invariant I-07)
  4. Credentials in agent output scanned (R4)
  5. On misbehavior, kill-switch can terminate (R3, invariant I-09)
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable


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
    allowed_tools: list[str] = field(default_factory=lambda: ["git", "npm", "cargo", "python", "go", "make"])
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
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TrackedSession:
    """A tracked coding agent session with AumOS security controls."""

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

    def _check_tool_allowed(self, command: str) -> bool:
        """Check if the command's base tool is in the allowed list."""
        base = command.strip().split()[0] if command.strip() else ""
        # Handle paths like /usr/bin/git
        base = os.path.basename(base)
        return any(base == tool or base.endswith(tool) for tool in self.config.allowed_tools)

    def _emit_receipt(self, tool: str, command: str, outcome: str, secrets: list[str] | None = None) -> dict[str, Any]:
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

        # Check tool allowlist
        if not self._check_tool_allowed(command):
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

        # Run the command
        try:
            effective_timeout = timeout or self.config.max_duration_seconds
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                cwd=self.config.working_dir,
            )
            stdout = proc.stdout
            stderr = proc.stderr
            exit_code = proc.returncode
            outcome = "committed" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired:
            stdout = ""
            stderr = f"command timed out after {effective_timeout}s"
            exit_code = -1
            outcome = "failed"
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
            self._emit_receipt(tool="kill_switch", command=f"kill: {reason}", outcome="killed")

    def close(self) -> SessionResult:
        """Close the session and return the summary."""
        if not self._killed and self.status == SessionStatus.ACTIVE:
            self.status = SessionStatus.COMPLETED
            self.result.status = SessionStatus.COMPLETED
        self.result.ended_at = _utcnow()
        self.result.duration_seconds = time.monotonic() - self._start_time
        return self.result


@contextmanager
def secure_session(config: HarnessConfig):
    """Context manager that wraps a coding agent session with AumOS security.

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
        content = open(claude_md, encoding="utf-8").read()
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
        content = open(agents_md, encoding="utf-8").read()
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

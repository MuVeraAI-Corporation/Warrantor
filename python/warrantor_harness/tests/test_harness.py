"""Tests for warrantor_harness: session lifecycle, file tracking, secrets, kill-switch, config parsing."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import pytest

from warrantor_harness import (
    AgentType,
    HarnessConfig,
    SessionStatus,
    TrackedSession,
    parse_claude_code_config,
    parse_codex_config,
    parse_cursor_config,
    secure_session,
)


def test_session_lifecycle() -> None:
    config = HarnessConfig(agent_type=AgentType.GENERIC, working_dir=".")
    session = TrackedSession(config)
    assert session.status is SessionStatus.ACTIVE
    result = session.close()
    assert result.status is SessionStatus.COMPLETED
    assert result.session_id is not None
    assert result.duration_seconds >= 0


def test_secure_session_context_manager() -> None:
    config = HarnessConfig(agent_type=AgentType.CLAUDE_CODE, working_dir=".")
    with secure_session(config) as session:
        assert session.status is SessionStatus.ACTIVE
    assert session.result.status is SessionStatus.COMPLETED


def test_file_access_tracking() -> None:
    session = TrackedSession(HarnessConfig(working_dir="."))
    session.track_file_access("/tmp/test.py", "read")
    session.track_file_access("/tmp/out.txt", "write")
    assert len(session.result.file_accesses) == 2
    assert session.result.file_accesses[0].mode == "read"
    session.close()


def test_secret_scanning_clean() -> None:
    session = TrackedSession(HarnessConfig(working_dir="."))
    findings = session.scan_output("just a normal log line")
    assert findings == []
    session.close()


def test_secret_scanning_detects_aws_key() -> None:
    session = TrackedSession(HarnessConfig(working_dir="."))
    findings = session.scan_output("config: AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert "AWS Access Key" in findings
    session.close()


def test_secret_scanning_detects_github_pat() -> None:
    session = TrackedSession(HarnessConfig(working_dir="."))
    findings = session.scan_output("token: ghp_" + "a" * 36)
    assert "GitHub PAT" in findings
    session.close()


def test_secret_scanning_detects_multiple() -> None:
    session = TrackedSession(HarnessConfig(working_dir="."))
    text = "a=AKIAIOSFODNN7EXAMPLE b=ghp_" + "b" * 36
    findings = session.scan_output(text)
    assert len(findings) >= 2
    session.close()


def test_run_agent_blocks_disallowed_tool() -> None:
    config = HarnessConfig(working_dir=".", allowed_tools=["git"])
    session = TrackedSession(config)
    result = session.run_agent("rm -rf /")
    assert result["exit_code"] == -1
    assert "not allowed" in result["error"]
    assert result["receipt"]["outcome"] == "failed"
    session.close()


def test_run_agent_executes_allowed_command() -> None:
    config = HarnessConfig(working_dir=".", allowed_tools=["echo"])
    session = TrackedSession(config)
    result = session.run_agent("echo hello_world")
    assert result["exit_code"] == 0
    assert "hello_world" in result["stdout"]
    assert result["receipt"]["outcome"] == "committed"
    assert session.result.action_count == 1
    session.close()


def test_kill_switch_terminates_session() -> None:
    session = TrackedSession(HarnessConfig(working_dir="."))
    session.kill("behavioral anomaly detected")
    assert session.status is SessionStatus.KILLED
    assert session.result.kill_reason == "behavioral anomaly detected"
    # Subsequent commands should fail
    result = session.run_agent("echo test")
    assert result.get("error") == "session killed"
    session.close()


def test_kill_on_secret_exposure() -> None:
    config = HarnessConfig(working_dir=".", allowed_tools=["echo"], kill_on_secret_exposure=True)
    session = TrackedSession(config)
    # echo a fake AWS key — should trigger kill
    result = session.run_agent("echo AKIAIOSFODNN7EXAMPLE")
    assert session.status is SessionStatus.KILLED
    assert "AWS Access Key" in result["secrets_found"]
    assert session.result.secrets_found >= 1
    session.close()


def test_no_kill_when_disabled() -> None:
    config = HarnessConfig(working_dir=".", allowed_tools=["echo"], kill_on_secret_exposure=False)
    session = TrackedSession(config)
    result = session.run_agent("echo AKIAIOSFODNN7EXAMPLE")
    assert session.status is SessionStatus.ACTIVE
    assert "AWS Access Key" in result["secrets_found"]
    session.close()


def test_receipt_emission() -> None:
    session = TrackedSession(HarnessConfig(working_dir=".", allowed_tools=["echo"]))
    session.run_agent("echo test")
    assert len(session.result.receipts) == 1
    r = session.result.receipts[0]
    assert r["actor"] == "agent:generic"
    assert r["tool"] == "echo"
    assert r["outcome"] == "committed"
    assert "aar-" in r["id"]
    session.close()


def test_session_result_to_dict() -> None:
    session = TrackedSession(HarnessConfig(agent_type=AgentType.CURSOR, working_dir="."))
    session.run_agent("echo hi")
    result = session.close()
    d = result.to_dict()
    assert d["agent_type"] == "cursor"
    assert d["status"] == "completed"
    assert d["action_count"] == 1
    assert d["receipts"] == 1


def test_exception_in_context_kills_session() -> None:
    config = HarnessConfig(working_dir=".")
    with pytest.raises(RuntimeError), secure_session(config) as session:
        raise RuntimeError("test crash")
    assert session.result.status is SessionStatus.KILLED
    assert "exception" in session.result.kill_reason


def test_parse_claude_code_config_creates_config() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        config = parse_claude_code_config(tmpdir)
        assert config.agent_type is AgentType.CLAUDE_CODE
        assert config.working_dir == tmpdir


def test_parse_codex_config_creates_config() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        config = parse_codex_config(tmpdir)
        assert config.agent_type is AgentType.CODEX


def test_parse_cursor_config_sets_attestation() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a .cursorrules file
        with open(os.path.join(tmpdir, ".cursorrules"), "w") as f:
            f.write("# cursor rules")
        config = parse_cursor_config(tmpdir)
        assert config.agent_type is AgentType.CURSOR
        assert config.require_attestation is True


def test_timeout_kills_command() -> None:
    python_executable = os.path.basename(sys.executable)
    command = subprocess.list2cmdline([sys.executable, "-c", "import time; time.sleep(10)"])
    config = HarnessConfig(
        working_dir=".",
        allowed_tools=[python_executable],
        max_duration_seconds=1,
    )
    session = TrackedSession(config)
    result = session.run_agent(command, timeout=1)
    assert result["exit_code"] == -1
    assert "timed out" in result["stderr"]
    session.close()


class TestAX30CommandExecutionIsNotShellInterpreted:
    """The allowlist must gate the whole command, not its first token (AX-30).

    Previously: `command.split()[0]` was basenamed, matched with `endswith`, and the raw
    string was then handed to `subprocess.run(..., shell=True)`. Each of the three was
    independently sufficient to escape the allowlist.
    """

    @staticmethod
    def _session():
        return TrackedSession(HarnessConfig(allowed_tools=["git", "python"]))

    def test_chained_command_cannot_reach_a_shell(self) -> None:
        # `git; rm -rf /` parses to argv[0] == "git;", which is not an allowed tool.
        assert self._session()._check_tool_allowed("git; rm -rf /") is False
        # `git && curl x` keeps argv[0] == "git", so it runs -- but `&&` and `curl` arrive
        # as arguments TO git, never as a second command. That is the whole fix.
        assert self._session()._resolve_argv("git && curl evil.example") == [
            "git",
            "&&",
            "curl",
            "evil.example",
        ]

    def test_substitution_is_inert_rather_than_executed(self) -> None:
        # These ARE allowed -- argv[0] is genuinely `git`. The security property is that
        # with shell=False the rest is literal argument text, so nothing substitutes.
        assert self._session()._resolve_argv("git $(rm -rf /)") == ["git", "$(rm", "-rf", "/)"]
        assert self._session()._resolve_argv("git `rm -rf /`") == ["git", "`rm", "-rf", "/`"]

    def test_endswith_lookalike_is_refused(self) -> None:
        # "evilgit".endswith("git") was True under the old matcher.
        assert self._session()._check_tool_allowed("evilgit status") is False
        assert self._session()._check_tool_allowed("notpython x.py") is False

    def test_genuine_commands_still_allowed(self) -> None:
        session = self._session()
        assert session._check_tool_allowed("git status") is True
        assert session._check_tool_allowed("/usr/bin/git status") is True
        assert session._check_tool_allowed("python -c 'print(1)'") is True

    def test_unparseable_command_is_refused(self) -> None:
        assert self._session()._check_tool_allowed("git 'unbalanced") is False
        assert self._session()._check_tool_allowed("") is False
        assert self._session()._check_tool_allowed("   ") is False

    def test_argv_is_a_list_so_no_shell_can_reinterpret_it(self) -> None:
        argv = self._session()._resolve_argv("git commit -m 'a; b'")
        assert argv == ["git", "commit", "-m", "a; b"]
        # The semicolon survives as literal argument text, not as an operator.

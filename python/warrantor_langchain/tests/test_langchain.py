"""Tests for warrantor_langchain: AARs, secret scanning, kill-switch, tool gating."""

from __future__ import annotations

import pytest

from warrantor_langchain import (
    AAR,
    PermissionDenied,
    SecuredAgent,
    WarrantorCallback,
    WarrantorTool,
    has_langchain,
    scan_for_secrets,
    wrap_agent,
)


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------
def test_scan_clean_text() -> None:
    assert scan_for_secrets("just a normal log line") == []


def test_scan_detects_aws_key() -> None:
    findings = scan_for_secrets("config: AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert "AWS Access Key" in findings


def test_scan_detects_multiple() -> None:
    text = "a=AKIAIOSFODNN7EXAMPLE b=ghp_" + "b" * 36
    findings = scan_for_secrets(text)
    assert "AWS Access Key" in findings
    assert "GitHub PAT" in findings


# ---------------------------------------------------------------------------
# WarrantorCallback: LLM and tool recording
# ---------------------------------------------------------------------------
def test_callback_records_llm_start_end() -> None:
    cb = WarrantorCallback(identity="alice")
    cb.on_llm_start(serialized={"name": "gpt-4"}, prompts=["hi"], run_id="r1")
    cb.on_llm_end({"generations": [[{"text": "hello"}]]}, run_id="r1")
    assert len(cb.aars) == 1
    aar = cb.aars[0]
    assert isinstance(aar, AAR)
    assert aar.action_type == "llm"
    assert aar.action_name == "gpt-4"
    assert aar.identity == "alice"
    assert aar.completed_at >= aar.started_at


def test_callback_records_tool_call() -> None:
    cb = WarrantorCallback(identity="bob")
    cb.on_tool_start(serialized={"name": "calculator"}, input_str="2+2", run_id="t1")
    cb.on_tool_end("4", run_id="t1")
    assert len(cb.aars) == 1
    aar = cb.aars[0]
    assert aar.action_type == "tool"
    assert aar.action_name == "calculator"
    assert aar.outputs == {"output": "4"}


def test_callback_secret_in_output_recorded() -> None:
    cb = WarrantorCallback(identity="eve", kill_on_secret=False)
    cb.on_llm_start(serialized={"name": "model"}, prompts=["x"], run_id="s1")
    cb.on_llm_end({"text": "leaked AKIAIOSFODNN7EXAMPLE"}, run_id="s1")
    aar = cb.aars[0]
    assert "AWS Access Key" in aar.secret_findings
    assert aar.kill_switch_triggered is False  # kill_on_secret disabled


def test_callback_triggers_kill_switch_on_secret() -> None:
    triggered: list[AAR] = []
    cb = WarrantorCallback(
        identity="eve",
        kill_switch=lambda aar: triggered.append(aar),
        kill_on_secret=True,
    )
    cb.on_llm_start(serialized={"name": "model"}, prompts=["x"], run_id="s2")
    cb.on_llm_end({"text": "leaked AKIAIOSFODNN7EXAMPLE"}, run_id="s2")
    aar = cb.aars[0]
    assert aar.kill_switch_triggered is True
    assert len(triggered) == 1
    assert triggered[0].aar_id == aar.aar_id


def test_callback_sink_invoked_per_aar() -> None:
    sink: list[AAR] = []
    cb = WarrantorCallback(identity="x", sink=sink.append)
    cb.on_chain_start(serialized={"name": "agent"}, inputs={"q": "hi"}, run_id="c1")
    cb.on_chain_end({"output": "ok"}, run_id="c1")
    assert len(sink) == 1
    assert sink[0].action_type == "chain"


def test_callback_error_path_records_error() -> None:
    cb = WarrantorCallback(identity="x")
    cb.on_llm_start(serialized={"name": "m"}, prompts=["x"], run_id="e1")
    cb.on_llm_error(ValueError("boom"), run_id="e1")
    aar = cb.aars[0]
    assert "boom" in aar.error
    assert aar.completed_at >= aar.started_at


def test_callback_handles_missing_run_id() -> None:
    """When LangChain doesn't pass run_id we should still match by recency."""
    cb = WarrantorCallback(identity="x")
    cb.on_tool_start(serialized={"name": "t"}, input_str="hi")
    cb.on_tool_end("bye")
    assert len(cb.aars) == 1


# ---------------------------------------------------------------------------
# WarrantorTool: permission gating
# ---------------------------------------------------------------------------
def test_tool_runs_when_permitted() -> None:
    tool = WarrantorTool(
        name="adder",
        description="adds",
        func=lambda x: x + 1,
        permission="compute",
        identity="alice",
        permission_check=lambda ident, perm: True,
    )
    assert tool(5) == 6


def test_tool_denied_without_permission() -> None:
    tool = WarrantorTool(
        name="danger",
        description="d",
        func=lambda: "ok",
        permission="admin",
        identity="mallory",
        permission_check=lambda ident, perm: False,
    )
    with pytest.raises(PermissionDenied) as exc:
        tool()
    assert exc.value.identity == "mallory"
    assert exc.value.permission == "admin"


def test_tool_runs_without_check_when_no_check_supplied() -> None:
    tool = WarrantorTool(
        name="t",
        description="d",
        func=lambda: 42,
        permission="anything",
        identity="anon",
        permission_check=None,
    )
    assert tool() == 42


def test_tool_on_call_records_invocation() -> None:
    calls: list[tuple[str, dict, object]] = []
    tool = WarrantorTool(
        name="t",
        description="d",
        func=lambda x: x * 2,
        permission="p",
        identity="alice",
        permission_check=lambda i, p: True,
        on_call=lambda name, inputs, result: calls.append((name, inputs, result)),
    )
    assert tool(3) == 6
    assert len(calls) == 1
    assert calls[0][0] == "t"
    assert calls[0][2] == 6


# ---------------------------------------------------------------------------
# wrap_agent
# ---------------------------------------------------------------------------
def test_wrap_agent_attaches_callback() -> None:
    class FakeAgent:
        def __init__(self) -> None:
            self.callbacks: list = []

    agent = FakeAgent()
    secured = wrap_agent(agent, identity="alice", side_effect_class="write")
    assert isinstance(secured, SecuredAgent)
    assert secured.identity == "alice"
    assert secured.side_effect_class == "write"
    assert secured.callback in agent.callbacks


def test_wrap_agent_runs_through_callback() -> None:
    class FakeAgent:
        def __init__(self) -> None:
            self.callbacks: list = []

        def run(self, prompt: str) -> str:
            # Simulate an LLM call that the callback observes.
            for cb in self.callbacks:
                cb.on_llm_start(serialized={"name": "m"}, prompts=[prompt], run_id="r")
                cb.on_llm_end({"text": "leaked AKIAIOSFODNN7EXAMPLE"}, run_id="r")
            return "done"

    triggered: list[AAR] = []
    secured = wrap_agent(
        FakeAgent(),
        identity="alice",
        kill_switch=triggered.append,
    )
    secured.run("hi")
    assert len(secured.callback.aars) == 1
    assert secured.callback.aars[0].kill_switch_triggered is True
    assert len(triggered) == 1


# ---------------------------------------------------------------------------
# has_langchain interop
# ---------------------------------------------------------------------------
def test_has_langchain_returns_bool() -> None:
    assert isinstance(has_langchain(), bool)

"""Tests for warrantor_ocsf: AAR->OCSF conversion, sinks, forwarder stats."""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from warrantor_ocsf import (
    ACTIVITY_OTHER,
    ACTIVITY_UNKNOWN,
    CLASS_API_ACTIVITY,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_INFO,
    FileSink,
    ForwardStats,
    HTTPSink,
    OCSFForwarder,
    Sink,
    convert_aar_to_ocsf,
)


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------
def test_convert_basic_aar() -> None:
    aar = {
        "aar_id": "r1",
        "identity": "alice",
        "action_type": "tool",
        "action_name": "calc",
        "inputs": {"x": 1},
        "outputs": {"y": 2},
        "completed_at": 1700000000.0,
    }
    ocsf = convert_aar_to_ocsf(aar)
    assert ocsf["class_uid"] == CLASS_API_ACTIVITY
    assert ocsf["category_uid"] == 6
    # This AAR carries no side_effect_class, so the activity is genuinely unknown --
    # not "Create", which is what the hard-coded 1 used to claim for every event.
    assert ocsf["activity_id"] == ACTIVITY_UNKNOWN
    assert ocsf["severity_id"] == SEVERITY_INFO
    assert ocsf["actor"]["user"]["uid"] == "alice"
    assert ocsf["api"]["operation"] == "calc"
    assert ocsf["api"]["request"]["uid"] == "r1"
    assert ocsf["api"]["request"]["data"] == {"x": 1}
    assert ocsf["api"]["response"]["data"] == {"y": 2}
    assert ocsf["status"] == "Success"
    # OCSF timestamp_t is milliseconds, not seconds.
    assert ocsf["time"] == 1700000000 * 1000


def test_convert_secret_finding_marks_high_severity() -> None:
    aar = {
        "aar_id": "r2",
        "identity": "eve",
        "action_type": "llm",
        "action_name": "m",
        "secret_findings": ["AWS Access Key"],
        "completed_at": 1.0,
    }
    ocsf = convert_aar_to_ocsf(aar)
    assert ocsf["severity_id"] == SEVERITY_HIGH
    assert any(r["type"] == "credential" for r in ocsf["resources"])
    assert "AWS Access Key" in ocsf["message"]


def test_convert_kill_switch_stays_api_activity_at_critical_severity() -> None:
    """Kill-switch events are API Activity, flagged by severity.

    They were previously emitted as class 6007 -- which is Scan Activity, a class that defines no
    actor, api or resources attribute. The whole security payload was dropped by the schema.
    """
    aar = {
        "aar_id": "r3",
        "identity": "alice",
        "action_type": "tool",
        "action_name": "danger",
        "kill_switch_triggered": True,
        "completed_at": 1.0,
    }
    ocsf = convert_aar_to_ocsf(aar)
    assert ocsf["class_uid"] == CLASS_API_ACTIVITY
    assert ocsf["severity_id"] == SEVERITY_CRITICAL
    # The payload the 6007 class would have discarded must still be present.
    assert ocsf["actor"]["user"]["uid"] == "alice"
    assert ocsf["api"]["operation"] == "danger"
    assert ocsf["unmapped"]["kill_switch_triggered"] is True


def test_convert_attestation_uses_a_defined_activity_id() -> None:
    """OCSF 6003 defines no Authenticate activity; 5 was invented and failed validation."""
    aar = {
        "aar_id": "r4",
        "identity": "node-1",
        "action_type": "attestation",
        "action_name": "verify",
        "completed_at": 1.0,
    }
    ocsf = convert_aar_to_ocsf(aar)
    assert ocsf["class_uid"] == CLASS_API_ACTIVITY
    assert ocsf["activity_id"] == ACTIVITY_OTHER


def test_convert_error_marks_failure() -> None:
    aar = {"identity": "x", "error": "boom", "completed_at": 1.0}
    ocsf = convert_aar_to_ocsf(aar)
    assert ocsf["status"] == "Failure"
    assert ocsf["status_id"] == 2
    assert ocsf["api"]["response"]["code"] == 500


def test_convert_rejects_non_dict() -> None:
    with pytest.raises(TypeError):
        convert_aar_to_ocsf("nope")  # type: ignore[arg-type]


def test_convert_tolerates_empty_aar() -> None:
    ocsf = convert_aar_to_ocsf({})
    assert ocsf["class_uid"] == CLASS_API_ACTIVITY
    assert ocsf["actor"]["user"]["uid"] == "anonymous"


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------
def test_filesink_appends_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "out.jsonl"
    sink = FileSink(path)
    assert sink.send({"a": 1}) is True
    assert sink.send({"a": 2}) is True
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"a": 1}
    assert json.loads(lines[1]) == {"a": 2}


def test_filesink_creates_parent_dirs(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "out.jsonl"
    sink = FileSink(path)
    assert sink.send({"x": 1}) is True
    assert path.exists()


def test_httpsink_rejects_empty_url() -> None:
    with pytest.raises(ValueError):
        HTTPSink("")


def test_httpsink_posts_to_local_server() -> None:
    received: list[dict] = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            pass

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            received.append(payload)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        sink = HTTPSink(f"http://127.0.0.1:{port}/collector", token="t")
        assert sink.send({"class_uid": 6003}) is True
        assert len(received) == 1
        assert received[0]["class_uid"] == 6003
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Forwarder
# ---------------------------------------------------------------------------
def test_forwarder_stats_and_dispatch() -> None:
    fwd = OCSFForwarder()
    ok_sink: list[dict] = []
    fail_sink: list[dict] = []

    class _OkSink:
        def send(self, event: dict) -> bool:
            ok_sink.append(event)
            return True

    class _FailSink:
        def send(self, event: dict) -> bool:
            fail_sink.append(event)
            return False

    fwd.add_sink(_OkSink())
    fwd.add_sink(_FailSink())
    assert isinstance(fwd.stats, ForwardStats)
    assert fwd.forward({"aar_id": "a", "identity": "x"}) is True
    assert fwd.stats.forwarded == 1
    assert fwd.stats.succeeded == 1
    assert fwd.stats.failed == 0
    # Both sinks were called
    assert len(ok_sink) == 1
    assert len(fail_sink) == 1


def test_forwarder_all_sinks_fail_reports_failure() -> None:
    fwd = OCSFForwarder()

    class _Fail:
        def send(self, event: dict) -> bool:
            return False

    fwd.add_sink(_Fail())
    assert fwd.forward({"aar_id": "a"}) is False
    assert fwd.stats.failed == 1
    assert fwd.stats.succeeded == 0


def test_forwarder_no_sinks_returns_false() -> None:
    fwd = OCSFForwarder()
    assert fwd.forward({"aar_id": "a"}) is False
    assert fwd.stats.forwarded == 1
    assert fwd.stats.failed == 1


def test_forwarder_sink_exception_does_not_break_others() -> None:
    fwd = OCSFForwarder()
    ok_events: list[dict] = []

    class _Boom:
        def send(self, event: dict) -> bool:
            raise RuntimeError("sink exploded")

    class _Ok:
        def send(self, event: dict) -> bool:
            ok_events.append(event)
            return True

    fwd.add_sink(_Boom())
    fwd.add_sink(_Ok())
    assert fwd.forward({"aar_id": "a", "identity": "x"}) is True
    assert len(ok_events) == 1


def test_forwarder_batch_forward() -> None:
    fwd = OCSFForwarder()

    class _Sink:
        def __init__(self) -> None:
            self.n = 0

        def send(self, event: dict) -> bool:
            self.n += 1
            return True

    s = _Sink()
    fwd.add_sink(s)
    accepted = fwd.batch_forward([{"aar_id": str(i)} for i in range(5)])
    assert accepted == 5
    assert s.n == 5
    assert fwd.stats.forwarded == 5


def test_sink_protocol_runtime_checkable() -> None:
    class _GoodSink:
        def send(self, event: dict) -> bool:
            return True

    class _BadSink:  # no send method
        pass

    assert isinstance(_GoodSink(), Sink)
    assert not isinstance(_BadSink(), Sink)


def test_add_sink_rejects_non_sink() -> None:
    fwd = OCSFForwarder()
    with pytest.raises(TypeError):
        fwd.add_sink("not a sink")  # type: ignore[arg-type]


def test_reset_stats() -> None:
    fwd = OCSFForwarder()
    fwd.forward({"aar_id": "a"})
    fwd.reset_stats()
    assert fwd.stats.forwarded == 0

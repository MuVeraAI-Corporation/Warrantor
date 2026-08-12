"""Regression tests for standalone-mode subprocess handling.

The bug these pin down: ``_start_standalone`` used to spawn vLLM with
``stdout=PIPE, stderr=PIPE`` and never read either pipe. vLLM emits a large
volume of progress output while loading weights, so the OS pipe buffer filled
and the child blocked on ``write`` before it ever bound its port -- the server
was permanently "starting" and every health check reported unhealthy.

``ChattyServer`` below reproduces that shape faithfully: it writes far more than
any platform's pipe buffer, and only *then* binds its port. Under the old
implementation ``start()`` returns but the port never opens; under the fix the
output lands in a file and the child runs to completion.
"""

from __future__ import annotations

import socket
import sys
import time

import pytest

from warrantor_vllm import AttestedVLLMServer, HealthStatus

# Comfortably larger than the largest common pipe buffer (Linux 64 KiB,
# Windows 4 KiB, macOS 16 KiB), so a piped-and-undrained child is guaranteed
# to block rather than merely being likely to.
NOISE_BYTES = 512 * 1024

# Writes NOISE_BYTES to stdout, *then* binds the port and holds it. The
# ordering is what makes this a deadlock detector.
CHILD_SOURCE = """
import socket, sys, time
sys.stdout.write("x" * {noise})
sys.stdout.flush()
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", {port}))
s.listen(1)
sys.stdout.write("BOUND")
sys.stdout.flush()
time.sleep(30)
"""


class ChattyServer(AttestedVLLMServer):
    """Stands in for vLLM: same spawn path, no vllm install required."""

    def _vllm_importable(self) -> bool:
        return True

    def _build_command(self) -> list[str]:
        return [
            sys.executable,
            "-c",
            CHILD_SOURCE.format(noise=NOISE_BYTES, port=self.port),
        ]


def _port_is_bound(port: int, timeout_s: float = 20.0) -> bool:
    """Poll until something accepts on the port, or we give up."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.1)
    return False


@pytest.fixture
def chatty_server(tmp_path):
    server = ChattyServer(mode="standalone", log_dir=str(tmp_path))
    try:
        yield server
    finally:
        server.stop()


def test_verbose_child_still_binds_its_port(chatty_server):
    """The core regression: a child that out-writes the pipe buffer must not
    deadlock before binding. This hangs on the old PIPE-based implementation."""
    chatty_server.start("/models/fake")
    assert chatty_server.port is not None
    assert _port_is_bound(chatty_server.port), (
        "child never bound its port -- it is blocked writing to an undrained pipe"
    )


def test_child_output_is_captured_to_the_log_file(chatty_server):
    """Redirecting must not mean discarding: the output has to stay available
    for diagnosing startup failures."""
    chatty_server.start("/models/fake")
    assert _port_is_bound(chatty_server.port)

    log_path = chatty_server.server_log_path
    assert log_path is not None
    assert log_path.parent.exists()
    # The child writes the marker only after the full noise payload, so seeing
    # it proves every byte was accepted rather than blocking the writer.
    tail = chatty_server.read_server_log()
    assert tail.endswith("BOUND")
    assert log_path.stat().st_size >= NOISE_BYTES


def test_dead_child_reports_its_log_in_the_health_detail(tmp_path):
    """A server that exits during startup should say *why*, not just 'not
    running' -- the log tail is the only clue an operator has."""

    class FailingServer(ChattyServer):
        def _build_command(self) -> list[str]:
            return [
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('CUDA out of memory'); sys.exit(3)",
            ]

    server = FailingServer(mode="standalone", log_dir=str(tmp_path))
    try:
        server.start("/models/fake")
        # Give the short-lived child time to exit.
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and server._process.poll() is None:
            time.sleep(0.05)

        report = server.detailed_health_check()
        assert report.status is HealthStatus.UNHEALTHY
        assert "exit=3" in report.detail
        assert "CUDA out of memory" in report.detail
    finally:
        server.stop()


def test_stop_closes_the_log_handle(chatty_server):
    """Leaking the handle would keep the file locked on Windows and leak an fd
    everywhere else."""
    chatty_server.start("/models/fake")
    assert chatty_server._log_handle is not None
    chatty_server.stop()
    assert chatty_server._log_handle is None


def test_mock_mode_has_no_log_file():
    """Mock mode spawns nothing, so there is nothing to log."""
    server = AttestedVLLMServer(mode="mock")
    server.start("/models/fake")
    try:
        assert server.server_log_path is None
        assert server.read_server_log() == ""
    finally:
        server.stop()

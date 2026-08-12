"""W0 regression tests: an agent must not outlive its supervision.

These drive real processes rather than mocks, because the whole point of W0 is that the guarantee
comes from the operating system rather than from Python cooperating. A mocked ``Popen`` would prove
nothing about whether the kernel actually kills the tree.

Two distinct holes are covered:

* **Orphaning** -- the harness dies, the agent keeps running. Tested by spawning a real harness in
  a subprocess, killing it without cleanup, and checking whether the grandchild is still alive.
* **Escape by descent** -- a command that forks outlives its own deadline, because
  ``subprocess.run(timeout=...)`` only ever killed the direct child.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import time

import pytest

from warrantor_harness import AgentType, HarnessConfig, TrackedSession
from warrantor_harness._lifetime import ProcessSupervisor, describe_linkage


def _alive(pid: int) -> bool:
    """Is this PID still running? Uses the platform's own view, not Python's."""
    if sys.platform == "win32":
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH", "/FO", "CSV"],
            capture_output=True,
            text=True,
            check=False,
        )
        return f'"{pid}"' in out.stdout
    try:
        import os

        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False
    return True


def _wait_gone(pid: int, timeout: float = 20.0) -> bool:
    """Poll until the PID disappears, or give up. Returns True if it is gone."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.15)
    return not _alive(pid)


# --- the linkage is reported honestly -------------------------------------------------


def test_linkage_is_described_rather_than_assumed():
    """A caller must be able to ask what the OS actually guarantees here, because the answer
    differs by platform and an unreported gap is how a false sense of safety forms."""
    linkage = describe_linkage()
    assert linkage.mechanism
    assert linkage.detail
    if sys.platform == "win32":
        assert linkage.survives_supervisor_death, "job objects give this guarantee on Windows"
        assert linkage.covers_descendants
    elif sys.platform.startswith("linux"):
        assert linkage.survives_supervisor_death, "PR_SET_PDEATHSIG gives this on Linux"
    else:
        # macOS/BSD have no parent-death signal. Claiming otherwise would be the bug.
        assert not linkage.survives_supervisor_death


def test_session_exposes_its_linkage():
    session = TrackedSession(HarnessConfig(agent_type=AgentType.GENERIC, allowed_tools=["python"]))
    try:
        assert session.lifetime_linkage.mechanism
    finally:
        session.close()


# --- orphaning: the agent must die with its supervisor --------------------------------


ORPHAN_HARNESS = textwrap.dedent(
    """
    import sys, time
    sys.path.insert(0, {src!r})
    from warrantor_harness import AgentType, HarnessConfig, TrackedSession

    session = TrackedSession(
        HarnessConfig(agent_type=AgentType.GENERIC, allowed_tools=["python"],
                      max_duration_seconds=600)
    )
    # Spawn a long-lived child and report its pid, then block forever. The parent process is
    # killed from the test WITHOUT cleanup, exactly as a crash or a closed terminal would.
    import subprocess
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(600)"],
        **session._supervisor._popen_kwargs(),
    )
    if session._supervisor._job is not None:
        from warrantor_harness._lifetime import _assign_to_windows_job
        _assign_to_windows_job(session._supervisor._job, child.pid)
    print(child.pid, flush=True)
    time.sleep(600)
    """
)


@pytest.mark.skipif(
    not describe_linkage().survives_supervisor_death,
    reason="this platform has no parent-death primitive; the capability TTL is the bound",
)
def test_agent_does_not_outlive_a_killed_harness():
    """THE W0 test. Kill the harness the way a crash would -- no cleanup, no atexit -- and the
    agent it spawned must die with it.

    Before W0 the agent kept running: unsupervised, unbounded, with nothing scanning its output
    and nothing enforcing its deadline. Every other guarantee the harness makes is void while
    that is true.
    """
    src = str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src")
    harness = subprocess.Popen(
        [sys.executable, "-c", ORPHAN_HARNESS.format(src=src)],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert harness.stdout is not None
        line = harness.stdout.readline().strip()
        assert line.isdigit(), f"harness did not report a child pid: {line!r}"
        agent_pid = int(line)
        assert _alive(agent_pid), "sanity: the agent should be running before we kill the harness"

        # SIGKILL-equivalent: no cleanup code runs. This is the crash case.
        harness.kill()
        harness.wait(timeout=15)

        assert _wait_gone(agent_pid), (
            f"SECURITY: agent pid {agent_pid} outlived the harness that was supervising it"
        )
    finally:
        if harness.poll() is None:
            harness.kill()


# --- escape by descent: the deadline must bound the whole tree ------------------------


def test_timeout_kills_grandchildren_not_just_the_direct_child():
    """`subprocess.run(timeout=...)` kills only what it spawned. A command that forks -- make,
    npm, a shell one-liner -- left its children running past the deadline, so `--timeout` bounded
    one process rather than the work."""
    with ProcessSupervisor() as supervisor:
        # Parent spawns a long-lived grandchild, prints its pid, then sleeps past the deadline.
        code = (
            "import subprocess, sys, time; "
            "g = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)']); "
            "print(g.pid, flush=True); time.sleep(600)"
        )
        # Run it directly so we can capture the grandchild pid before the timeout fires.
        process = subprocess.Popen(
            [sys.executable, "-c", code],
            stdout=subprocess.PIPE,
            text=True,
            **supervisor._popen_kwargs(),
        )
        if supervisor._job is not None:
            from warrantor_harness._lifetime import _assign_to_windows_job

            _assign_to_windows_job(supervisor._job, process.pid)
        supervisor._children.append(process)

        assert process.stdout is not None
        grandchild_pid = int(process.stdout.readline().strip())
        assert _alive(grandchild_pid), "sanity: grandchild should be running"

        supervisor._terminate_tree(process)

        assert _wait_gone(grandchild_pid), (
            f"grandchild {grandchild_pid} survived termination of its parent -- the deadline "
            "bounds one process, not the process tree"
        )


def test_supervised_run_still_returns_output_normally():
    """The supervision must not change ordinary behaviour."""
    with ProcessSupervisor() as supervisor:
        result = supervisor.run([sys.executable, "-c", "print('hello')"], timeout=30)
        assert result.returncode == 0
        assert "hello" in result.stdout
        assert not result.timed_out


def test_supervised_run_reports_timeout():
    with ProcessSupervisor() as supervisor:
        result = supervisor.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=1)
        assert result.timed_out
        assert result.returncode == -1
        assert "timed out" in result.stderr


def test_kill_terminates_a_running_tree_immediately():
    """kill() used to set a flag checked on the NEXT command, so a long-running command already in
    flight kept going after a secret was found in its own output."""
    session = TrackedSession(HarnessConfig(agent_type=AgentType.GENERIC, allowed_tools=["python"]))
    try:
        with ProcessSupervisor() as supervisor:
            process = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(600)"],
                **supervisor._popen_kwargs(),
            )
            supervisor._children.append(process)
            session._supervisor = supervisor
            assert _alive(process.pid)

            session.kill("secret exposure detected: test")

            assert _wait_gone(process.pid), (
                "kill() recorded the decision but did not stop the running command"
            )
    finally:
        session.close()

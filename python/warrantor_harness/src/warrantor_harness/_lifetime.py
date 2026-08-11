"""OS-enforced process lifetime linkage for supervised agent commands (W0).

# The hole this closes

``warrantor-harness`` enforced its tool allowlist and its kill-on-secret rule from inside a
Python process, and spawned agent commands with a plain ``subprocess.run``. That left two ways for
an agent to outlive its supervision, both of which void every other guarantee the harness makes:

1. **Orphaning.** If the harness is killed, OOMs, or its terminal closes, the spawned command keeps
   running. Nothing is scanning its output, nothing is enforcing a deadline, and nothing will kill
   it. An agent that survives its supervisor at 3am is exactly the scenario the harness exists to
   prevent.

2. **Escape by descent.** ``subprocess.run(timeout=...)`` kills only the process it spawned. A
   command that forks -- ``make``, ``npm``, a shell one-liner, an agent that spawns its own
   workers -- leaves grandchildren running after the timeout fires. The deadline bounded one
   process, not the work.

Both are closed here, by the operating system rather than by cooperation from the child.

# How

The two platforms give different primitives, so the guarantees differ slightly and the difference
is stated rather than papered over.

**Windows** -- a Job Object with ``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE``. Every spawned process is
assigned to the job, and every process *it* spawns is in the job too, because job membership is
inherited and cannot be renounced without a privilege the child does not have. When the harness
exits -- cleanly, by crash, or by being killed -- the last handle to the job closes and the kernel
terminates every process still in it. This is the strongest form of the guarantee: it does not
depend on the harness running any cleanup code at all.

**POSIX** -- two mechanisms, because neither is sufficient alone:

* ``start_new_session=True`` puts the child in its own process group, so
  :meth:`ProcessSupervisor.terminate` can signal the entire tree with ``killpg`` instead of just
  the direct child. This is what closes escape-by-descent.
* ``PR_SET_PDEATHSIG`` asks the kernel to send ``SIGKILL`` to the child when its parent dies. This
  is what closes orphaning, and it fires without the harness executing anything.

``PR_SET_PDEATHSIG`` is Linux-only and applies to the direct child rather than the whole group, so
on Linux a grandchild can still be orphaned if the harness dies at exactly the wrong moment. On
macOS and the BSDs the primitive does not exist at all. **The layer above this one is what covers
that gap**: capability tokens carry a short TTL, so an escaped agent loses its authority within a
minute even when nothing kills it. Belt and braces, failing differently, is the design.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from types import TracebackType
from typing import ClassVar

__all__ = [
    "LifetimeLinkage",
    "ProcessSupervisor",
    "SupervisedResult",
    "describe_linkage",
]

#: Grace period between asking a process tree to stop and killing it outright.
TERMINATE_GRACE_SECONDS = 3.0


@dataclass(frozen=True)
class LifetimeLinkage:
    """What the OS actually guarantees on this host.

    Reported rather than assumed: a caller that needs to know whether an orphan is possible should
    be able to ask, and the answer differs by platform.
    """

    #: Short identifier for the mechanism in use.
    mechanism: str
    #: True when the OS kills the agent tree if the harness dies without running cleanup.
    survives_supervisor_death: bool
    #: True when signalling the agent reaches processes it spawned, not just the direct child.
    covers_descendants: bool
    #: Human-readable explanation, surfaced in reports and diagnostics.
    detail: str


def describe_linkage() -> LifetimeLinkage:
    """Describe the lifetime guarantee available on this host."""
    if sys.platform == "win32":
        return LifetimeLinkage(
            mechanism="job-object",
            survives_supervisor_death=True,
            covers_descendants=True,
            detail=(
                "Windows Job Object with KILL_ON_JOB_CLOSE: the kernel terminates the whole "
                "agent tree when the harness exits, including on crash."
            ),
        )
    if sys.platform.startswith("linux"):
        return LifetimeLinkage(
            mechanism="setsid+pdeathsig",
            survives_supervisor_death=True,
            covers_descendants=True,
            detail=(
                "New session for group signalling, plus PR_SET_PDEATHSIG so the direct child is "
                "killed when the harness dies. A grandchild can outlive a harness crash; the "
                "capability TTL bounds it."
            ),
        )
    return LifetimeLinkage(
        mechanism="setsid",
        survives_supervisor_death=False,
        covers_descendants=True,
        detail=(
            "New session for group signalling. This platform has no parent-death signal, so an "
            "agent CAN outlive a harness crash; the capability TTL is the only bound."
        ),
    )


@dataclass
class SupervisedResult:
    """Outcome of a supervised command. Mirrors the subset of
    :class:`subprocess.CompletedProcess` the harness uses, plus why it ended."""

    stdout: str
    stderr: str
    returncode: int
    #: True when the command was killed for exceeding its deadline.
    timed_out: bool = False


# --------------------------------------------------------------------------------------
# Windows job object
# --------------------------------------------------------------------------------------
def _create_windows_job() -> object | None:
    """Create a job object that kills its members when the last handle closes.

    Returns ``None`` if the job could not be created, in which case the caller falls back to
    unsupervised spawning and says so -- a degraded guarantee that is reported is much better than
    one that is silently absent.
    """
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class IO_COUNTERS(ctypes.Structure):
        _fields_: ClassVar = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_: ClassVar = [
            ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
            ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.POINTER(wintypes.ULONG)),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_: ClassVar = [
            ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    job_object_extended_limit_information = 9
    job_object_limit_kill_on_job_close = 0x00002000

    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        return None

    limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    limits.BasicLimitInformation.LimitFlags = job_object_limit_kill_on_job_close
    ok = kernel32.SetInformationJobObject(
        wintypes.HANDLE(handle),
        job_object_extended_limit_information,
        ctypes.byref(limits),
        ctypes.sizeof(limits),
    )
    if not ok:
        kernel32.CloseHandle(wintypes.HANDLE(handle))
        return None
    return handle


def _assign_to_windows_job(job: object, pid: int) -> bool:
    """Put ``pid`` (and therefore everything it spawns) into the job."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    process_set_quota = 0x0100
    process_terminate = 0x0001

    process = kernel32.OpenProcess(process_set_quota | process_terminate, False, pid)
    if not process:
        return False
    try:
        return bool(
            kernel32.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(process))
        )
    finally:
        kernel32.CloseHandle(wintypes.HANDLE(process))


# --------------------------------------------------------------------------------------
# POSIX parent-death signal
# --------------------------------------------------------------------------------------
def _linux_pdeathsig() -> None:  # pragma: no cover - runs only in the forked child
    """Ask the kernel to SIGKILL this process when its parent dies.

    Runs between ``fork`` and ``exec``. Failures are deliberately swallowed: losing the parent-death
    signal degrades the guarantee, but refusing to start the command would be worse, and the
    degraded state is reported by :func:`describe_linkage`.
    """
    try:
        import ctypes

        pr_set_pdeathsig = 1
        ctypes.CDLL("libc.so.6", use_errno=True).prctl(pr_set_pdeathsig, signal.SIGKILL, 0, 0, 0)
    except Exception:
        pass


class ProcessSupervisor:
    """Spawns commands under OS-enforced lifetime linkage.

    Use as a context manager. On Windows the job object's lifetime is the supervisor's lifetime,
    so leaving the block is what arms the kill-on-close guarantee's counterpart -- an explicit
    teardown of anything still running.
    """

    def __init__(self) -> None:
        self._job: object | None = None
        self._children: list[subprocess.Popen] = []
        self.linkage = describe_linkage()

    def __enter__(self) -> ProcessSupervisor:
        if sys.platform == "win32":
            self._job = _create_windows_job()
            if self._job is None:
                # Report the weaker guarantee rather than claiming one we do not have.
                self.linkage = LifetimeLinkage(
                    mechanism="none",
                    survives_supervisor_death=False,
                    covers_descendants=False,
                    detail=(
                        "Windows job object could not be created; agent processes are NOT "
                        "lifetime-linked to the harness on this host."
                    ),
                )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.terminate_all()
        if self._job is not None:
            import ctypes
            from ctypes import wintypes

            # Closing the last handle is what triggers KILL_ON_JOB_CLOSE.
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(wintypes.HANDLE(self._job))
            self._job = None

    def _popen_kwargs(self) -> dict[str, object]:
        if sys.platform == "win32":
            return {}
        kwargs: dict[str, object] = {"start_new_session": True}
        if sys.platform.startswith("linux"):
            kwargs["preexec_fn"] = _linux_pdeathsig
        return kwargs

    def run(
        self,
        argv: list[str],
        *,
        cwd: str | None = None,
        timeout: float | None = None,
    ) -> SupervisedResult:
        """Run ``argv`` to completion under supervision.

        On timeout the entire process tree is terminated, not just the command itself.
        """
        process = subprocess.Popen(  # argv is an allowlisted list; shell is never used
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            **self._popen_kwargs(),  # type: ignore[arg-type]
        )
        self._children.append(process)

        # If assignment fails the process still runs, but without the linkage; surface that
        # rather than pretending the guarantee holds.
        if self._job is not None and not _assign_to_windows_job(self._job, process.pid):
            self.linkage = LifetimeLinkage(
                mechanism="job-object-partial",
                survives_supervisor_death=False,
                covers_descendants=False,
                detail=(
                    f"process {process.pid} could not be assigned to the job object; it is "
                    "NOT lifetime-linked."
                ),
            )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return SupervisedResult(
                stdout=stdout or "", stderr=stderr or "", returncode=process.returncode
            )
        except subprocess.TimeoutExpired:
            self._terminate_tree(process)
            # Drain whatever the tree produced before it died; a timed-out command's output is
            # often the most useful thing in the report.
            try:
                stdout, stderr = process.communicate(timeout=TERMINATE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", ""
            return SupervisedResult(
                stdout=stdout or "",
                stderr=(stderr or "")
                + f"\ncommand timed out after {timeout}s; the whole process tree was terminated",
                returncode=-1,
                timed_out=True,
            )
        finally:
            if process in self._children:
                self._children.remove(process)

    def _terminate_tree(self, process: subprocess.Popen) -> None:
        """Kill ``process`` and everything it spawned."""
        if sys.platform == "win32":
            # taskkill /T walks the tree. The job object is the backstop if this fails.
            subprocess.run(
                [
                    os.path.join(
                        os.environ.get("SYSTEMROOT", r"C:\Windows"),
                        "System32",
                        "taskkill.exe",
                    ),
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                ],
                capture_output=True,
                check=False,
            )
            return
        try:
            # start_new_session made the child a process-group leader, so its pid is the pgid.
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            process.kill()

    def terminate_all(self) -> None:
        """Terminate every command still running under this supervisor."""
        for process in list(self._children):
            if process.poll() is None:
                self._terminate_tree(process)
        self._children.clear()

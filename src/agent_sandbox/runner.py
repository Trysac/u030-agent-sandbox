"""Process runners: the ``ProcessRunner`` protocol and the guarded ``SubprocessRunner``."""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import IO, Any, Protocol

from .errors import SandboxError
from .models import RunResult

_log = logging.getLogger(__name__)

_CHUNK_BYTES = 64 * 1024
_JOIN_TIMEOUT_SECONDS = 5.0


class ProcessRunner(Protocol):
    """Anything able to execute an already vetted argv."""

    def run(
        self,
        argv: list[str],
        cwd: Path,
        env: dict[str, str],
        timeout: float,
        max_bytes: int,
    ) -> RunResult:
        """Run ``argv`` in ``cwd`` with exactly ``env`` and return the captured result."""
        ...


class _Capture:
    """Keeps the first ``limit`` bytes of a stream and remembers whether more arrived."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.truncated = False

    def feed(self, chunk: bytes) -> None:
        remaining = max(self.limit - len(self.data), 0)
        self.data += chunk[:remaining]
        if len(chunk) > remaining:
            self.truncated = True


def _drain(stream: IO[bytes], capture: _Capture) -> None:
    """Read 64 KiB chunks until EOF, keeping the head and discarding the rest."""
    try:
        while True:
            chunk = stream.read(_CHUNK_BYTES)
            if not chunk:
                break
            capture.feed(chunk)
    except (OSError, ValueError):
        _log.debug("output reader stopped early")
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _start_reader(stream: IO[bytes] | None, capture: _Capture) -> threading.Thread:
    if stream is None:  # pragma: no cover - Popen always provides the pipes
        raise SandboxError("spawn_failed", "process pipes are unavailable")
    thread = threading.Thread(target=_drain, args=(stream, capture), daemon=True)
    thread.start()
    return thread


def _join_all(threads: list[threading.Thread], timeout: float) -> None:
    for thread in threads:
        thread.join(timeout)


def _group_kwargs() -> dict[str, Any]:
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows only
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _taskkill(pid: int) -> None:  # pragma: no cover - exercised on Windows only
    system_root = os.environ.get("SYSTEMROOT", "C:/Windows")
    exe = os.path.join(system_root, "System32", "taskkill.exe")
    command = [exe, "/F", "/T", "/PID", str(pid)]
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        subprocess.run(command, capture_output=True, check=False, timeout=10)


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    """Kill the process and everything in its group (POSIX) or tree (Windows)."""
    if sys.platform == "win32":  # pragma: no cover - exercised on Windows only
        _taskkill(proc.pid)
        with contextlib.suppress(OSError):
            proc.kill()
        return
    with contextlib.suppress(OSError):
        os.killpg(proc.pid, signal.SIGKILL)


def _spawn(argv: list[str], cwd: Path, env: dict[str, str]) -> subprocess.Popen[bytes]:
    try:
        proc: subprocess.Popen[bytes] = subprocess.Popen(
            argv,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            bufsize=0,
            **_group_kwargs(),
        )
    except (OSError, ValueError) as exc:
        message = f"process could not be started: {type(exc).__name__}"
        raise SandboxError("spawn_failed", message) from None
    return proc


class SubprocessRunner:
    """Default runner: ``shell=False``, own process group, timeout and capped output.

    On timeout the whole process group (POSIX, ``os.killpg`` with SIGKILL) or tree (Windows,
    ``taskkill.exe /F /T`` from the absolute System32 path) is killed. Two reader threads read
    64 KiB chunks, keep the first ``max_bytes`` of each stream and drain and discard the rest;
    they are joined with a bound so a stray pipe holder cannot hang the caller.

    Args:
        clock: Monotonic clock used for ``duration_seconds``.
        join_timeout: Seconds to wait for reader threads and for a killed process.
    """

    def __init__(
        self,
        clock: Callable[[], float] = time.monotonic,
        join_timeout: float = _JOIN_TIMEOUT_SECONDS,
    ) -> None:
        self._clock = clock
        self._join_timeout = join_timeout

    def run(
        self,
        argv: list[str],
        cwd: Path,
        env: dict[str, str],
        timeout: float,
        max_bytes: int,
    ) -> RunResult:
        """Run ``argv`` and return its result.

        Raises:
            SandboxError: with code ``spawn_failed`` when the process cannot be started.
        """
        start = self._clock()
        proc = _spawn(argv, cwd, env)
        stdout = _Capture(max_bytes)
        stderr = _Capture(max_bytes)
        threads: list[threading.Thread] = []
        timed_out = False
        exit_code: int | None = None
        try:
            threads.append(_start_reader(proc.stdout, stdout))
            threads.append(_start_reader(proc.stderr, stderr))
            try:
                exit_code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _log.warning("process exceeded its timeout; killing the process tree")
                _kill_tree(proc)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=self._join_timeout)
            _join_all(threads, self._join_timeout)
            if not timed_out and any(thread.is_alive() for thread in threads):
                _log.warning("output pipes still open after exit; killing leftover processes")
                _kill_tree(proc)
                _join_all(threads, self._join_timeout)
        finally:
            if proc.poll() is None:
                _kill_tree(proc)
        duration = self._clock() - start
        return RunResult(
            exit_code=exit_code,
            stdout=bytes(stdout.data).decode("utf-8", errors="replace"),
            stderr=bytes(stderr.data).decode("utf-8", errors="replace"),
            timed_out=timed_out,
            truncated=stdout.truncated or stderr.truncated,
            duration_seconds=duration,
        )

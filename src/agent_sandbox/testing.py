"""Test doubles: ``FakeProcessRunner`` records calls and never starts a process."""

from __future__ import annotations

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .models import RunResult

__all__ = ["FakeProcessRunner", "RecordedCall"]

_DEFAULT_RESULT = RunResult(
    exit_code=0,
    stdout="",
    stderr="",
    timed_out=False,
    truncated=False,
    duration_seconds=0.0,
)


@dataclass(frozen=True)
class RecordedCall:
    """One call received by ``FakeProcessRunner``."""

    argv: tuple[str, ...]
    cwd: Path
    env: dict[str, str]
    timeout: float
    max_bytes: int


class FakeProcessRunner:
    """A ``ProcessRunner`` that records its calls and replays canned results.

    Args:
        results: Results returned in order, one per call.
        default: Result returned once ``results`` is exhausted (exit code 0, no output).
        max_calls: How many recorded calls are kept; the oldest are evicted first.
    """

    def __init__(
        self,
        results: Sequence[RunResult] = (),
        default: RunResult | None = None,
        max_calls: int = 1000,
    ) -> None:
        self._results = deque(results)
        self._default = default if default is not None else _DEFAULT_RESULT
        self._calls: deque[RecordedCall] = deque(maxlen=max(max_calls, 1))

    @property
    def calls(self) -> list[RecordedCall]:
        """The recorded calls, oldest first."""
        return list(self._calls)

    def run(
        self,
        argv: list[str],
        cwd: Path,
        env: dict[str, str],
        timeout: float,
        max_bytes: int,
    ) -> RunResult:
        """Record the call and return the next canned result."""
        self._calls.append(RecordedCall(tuple(argv), cwd, dict(env), timeout, max_bytes))
        if self._results:
            return self._results.popleft()
        return self._default

"""Tests for ``SubprocessRunner``, ``FakeProcessRunner`` and guarded end-to-end runs."""

from __future__ import annotations

import os
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from agent_sandbox import Policy, RunResult, Sandbox, SandboxError, SubprocessRunner
from agent_sandbox.testing import FakeProcessRunner, RecordedCall

PYTHON = sys.executable
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")

GRANDCHILD = (
    "import subprocess, sys, time; "
    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)']); "
    "time.sleep(60)"
)


def run_code(runner: SubprocessRunner, code: str, cwd: Path, limit: int = 1000) -> RunResult:
    return runner.run([PYTHON, "-c", code], cwd, dict(os.environ), 10.0, limit)


def test_exit_code_and_streams(root: Path) -> None:
    code = "import sys; sys.stdout.write('out'); sys.stderr.write('err'); sys.exit(3)"
    result = run_code(SubprocessRunner(), code, root)
    assert (result.exit_code, result.stdout, result.stderr) == (3, "out", "err")
    assert result.timed_out is False
    assert result.truncated is False


def test_output_cap_boundary(loose: Policy, root: Path) -> None:
    capped = Sandbox(replace(loose, max_output_bytes=1000))
    exact = capped.run([PYTHON, "-c", "import sys; sys.stdout.write('x' * 1000)"], cwd=root)
    assert exact.truncated is False
    assert exact.stdout == "x" * 1000
    over = capped.run([PYTHON, "-c", "import sys; sys.stdout.write('x' * 1001)"], cwd=root)
    assert over.truncated is True
    assert over.stdout == "x" * 1000


def test_invalid_bytes_are_replaced(loose: Policy, root: Path) -> None:
    code = r"import sys; sys.stdout.buffer.write(b'\xff')"
    result = Sandbox(loose).run([PYTHON, "-c", code], cwd=root)
    assert result.stdout == "\ufffd"
    assert result.truncated is False


def test_stderr_overflow_marks_truncated(root: Path) -> None:
    code = "import sys; sys.stderr.write('e' * 50)"
    result = run_code(SubprocessRunner(), code, root, limit=10)
    assert result.truncated is True
    assert result.stderr == "e" * 10
    assert result.stdout == ""


def test_runaway_output_is_drained(root: Path) -> None:
    code = "import sys; sys.stdout.write('y' * 5_000_000)"
    result = run_code(SubprocessRunner(), code, root)
    assert result.exit_code == 0
    assert result.truncated is True
    assert result.stdout == "y" * 1000


def test_timeout_kills_the_process_tree(loose: Policy, root: Path) -> None:
    quick = Sandbox(replace(loose, timeout_seconds=0.5))
    result = quick.run([PYTHON, "-c", GRANDCHILD], cwd=root)
    assert result.timed_out is True
    assert result.exit_code is None
    assert result.duration_seconds < 30


@posix_only
def test_leftover_process_group_is_killed(root: Path) -> None:
    code = (
        "import subprocess, sys; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])"
    )
    result = run_code(SubprocessRunner(join_timeout=0.5), code, root)
    assert result.exit_code == 0
    assert result.timed_out is False
    assert result.duration_seconds < 30


def test_stdin_is_closed(root: Path) -> None:
    code = "import sys; sys.stdout.write(repr(sys.stdin.read()))"
    assert run_code(SubprocessRunner(), code, root).stdout == "''"


def test_duration_uses_the_injected_clock(root: Path) -> None:
    ticks = iter([10.0, 12.5])
    runner = SubprocessRunner(clock=lambda: next(ticks))
    assert run_code(runner, "pass", root).duration_seconds == 2.5


def test_spawn_failures_raise_a_typed_error(root: Path) -> None:
    runner = SubprocessRunner()
    for argv in (["/nonexistent/binary"], ["a\x00b"]):
        with pytest.raises(SandboxError) as info:
            runner.run(argv, root, {}, 5.0, 100)
        assert info.value.code == "spawn_failed"


def test_missing_working_directory_is_a_spawn_failure(loose: Policy, root: Path) -> None:
    with pytest.raises(SandboxError) as info:
        Sandbox(loose).run([PYTHON, "-c", "pass"], cwd=root / "missing")
    assert info.value.code == "spawn_failed"


@posix_only
def test_runner_passes_exactly_the_given_environment(root: Path) -> None:
    code = "import os; print(os.environ.get('ONLY'), os.environ.get('HOME'))"
    result = SubprocessRunner().run([PYTHON, "-c", code], root, {"ONLY": "1"}, 10.0, 100)
    assert result.stdout.strip() == "1 None"


@posix_only
def test_secrets_never_reach_the_child(
    loose: Policy,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_PAT", "value")
    monkeypatch.setenv("PATTERN", "kept")
    allow = frozenset({"GITHUB_PAT", "PATTERN", "PATH"})
    guarded = Sandbox(replace(loose, env_allow=allow))
    code = "import os; print(os.environ.get('GITHUB_PAT'), os.environ.get('PATTERN'))"
    result = guarded.run([PYTHON, "-c", code], cwd=root)
    assert result.stdout.strip() == "None kept"


def test_fake_runner_replays_results_then_default(root: Path) -> None:
    first = RunResult(1, "a", "b", False, False, 0.1)
    fake = FakeProcessRunner(results=[first])
    env = {"K": "v"}
    assert fake.run(["x"], root, env, 1.0, 10) == first
    env["K"] = "changed"
    assert fake.run(["y"], root, {}, 2.0, 20).exit_code == 0
    assert fake.calls == [
        RecordedCall(("x",), root, {"K": "v"}, 1.0, 10),
        RecordedCall(("y",), root, {}, 2.0, 20),
    ]


def test_fake_runner_custom_default(root: Path) -> None:
    fake = FakeProcessRunner(default=RunResult(7, "", "", False, False, 0.0))
    assert fake.run(["x"], root, {}, 1.0, 10).exit_code == 7


def test_fake_runner_bounds_recorded_calls(root: Path) -> None:
    fake = FakeProcessRunner(max_calls=2)
    for name in ("a", "b", "c"):
        fake.run([name], root, {}, 1.0, 10)
    assert [call.argv for call in fake.calls] == [("b",), ("c",)]
    assert len(FakeProcessRunner(max_calls=0).calls) == 0

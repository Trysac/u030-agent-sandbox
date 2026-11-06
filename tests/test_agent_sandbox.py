"""Tests for ``Policy``, ``Sandbox`` decisions, redaction, events and the audit log."""

from __future__ import annotations

import logging
import os
import shlex
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import agent_sandbox
from agent_sandbox import (
    DEFAULT_ENV_ALLOW,
    Decision,
    Policy,
    PolicyViolation,
    Sandbox,
    SandboxError,
    is_secret_name,
)
from agent_sandbox.testing import FakeProcessRunner

PYTHON = sys.executable
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX semantics")


@pytest.fixture
def sandbox(policy: Policy, fake: FakeProcessRunner) -> Sandbox:
    return Sandbox(policy, runner=fake)


def test_package_metadata() -> None:
    assert agent_sandbox.__version__ == "0.1.0"
    handlers = logging.getLogger("agent_sandbox").handlers
    assert any(isinstance(handler, logging.NullHandler) for handler in handlers)


def test_policy_defaults(policy: Policy) -> None:
    assert policy.timeout_seconds == 30.0
    assert policy.max_output_bytes == 1_000_000
    assert policy.reject_shell_metacharacters is True
    assert policy.max_audit_entries == 1000
    assert policy.env_allow == DEFAULT_ENV_ALLOW
    expected = {"PATH", "PATHEXT", "LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP"}
    assert frozenset(expected) == DEFAULT_ENV_ALLOW
    assert Sandbox(policy).policy is policy


def test_policy_rejects_executable_inside_root(root: Path) -> None:
    with pytest.raises(SandboxError) as info:
        Policy(allowed_executables=frozenset({root / "tool"}), allowed_roots=(root,))
    assert info.value.code == "invalid_policy"


@pytest.mark.parametrize(
    "change",
    [
        {"timeout_seconds": 0.0},
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": float("inf")},
        {"max_output_bytes": 0},
        {"max_audit_entries": 0},
        {"allowed_roots": (Path("relative"),)},
        {"allowed_executables": frozenset({Path("tool")})},
    ],
)
def test_policy_rejects_invalid_values(policy: Policy, change: dict[str, Any]) -> None:
    with pytest.raises(SandboxError) as info:
        replace(policy, **change)
    assert info.value.code == "invalid_policy"


def test_unlisted_binary_denied(sandbox: Sandbox, root: Path, fake: FakeProcessRunner) -> None:
    decision = sandbox.check(["curl", "x"], cwd=root)
    assert decision == Decision(allowed=False, reason="binary_not_allowed", argv=("curl", "x"))
    assert fake.calls == []
    with pytest.raises(PolicyViolation) as info:
        sandbox.run(["curl", "x"], cwd=root)
    assert info.value.reason == "binary_not_allowed"
    assert info.value.code == "policy_violation"
    assert isinstance(info.value, SandboxError)
    assert fake.calls == []


def test_violation_message_is_bounded(sandbox: Sandbox, root: Path) -> None:
    with pytest.raises(PolicyViolation) as info:
        sandbox.run(["curl", "x" * 500], cwd=root)
    message = str(info.value)
    assert message.startswith("binary_not_allowed: curl ")
    assert len(message) <= len("binary_not_allowed: ") + 200
    assert sandbox.check(["curl", "x" * 500], cwd=root).argv[1] == "x" * 200


def test_run_raises_for_every_denial(sandbox: Sandbox, root: Path) -> None:
    commands: dict[str, list[str]] = {
        "empty_command": [],
        "argv_too_long": [PYTHON, "x" * 5000],
        "shell_metacharacters": [PYTHON, "a;b"],
        "relative_executable": ["./tool"],
        "binary_not_allowed": ["curl", "x"],
        "path_outside_roots": [PYTHON, "../x"],
    }
    for reason, command in commands.items():
        with pytest.raises(PolicyViolation) as info:
            sandbox.run(command, cwd=root)
        assert info.value.reason == reason


@pytest.mark.parametrize("command", ["./tool", "bin/tool", "~/tool"])
def test_relative_executable_is_rejected(sandbox: Sandbox, root: Path, command: str) -> None:
    assert sandbox.check([command, "x"], cwd=root).reason == "relative_executable"


@posix_only
def test_symlink_in_root_is_rejected(sandbox: Sandbox, root: Path) -> None:
    link = root / "py"
    link.symlink_to(os.path.realpath(PYTHON))
    decision = sandbox.check([str(link), "-c", "pass"], cwd=root)
    assert decision.reason == "executable_in_roots"


@posix_only
def test_bare_name_is_resolved_on_the_scrubbed_path(
    policy: Policy,
    root: Path,
    fake: FakeProcessRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "tool").symlink_to(os.path.realpath(PYTHON))
    monkeypatch.setenv("PATH", str(bin_dir))
    sandbox = Sandbox(policy, runner=fake)
    assert sandbox.check(["tool", "-c", "pass"], cwd=root).allowed is True
    sandbox.run(["tool", "-c", "pass"], cwd=root)
    assert fake.calls[0].argv[0] == os.path.realpath(PYTHON)
    hidden = Sandbox(replace(policy, env_allow=frozenset()), runner=fake)
    assert hidden.check(["tool"], cwd=root).reason == "binary_not_allowed"


@posix_only
def test_path_hijack_is_rejected(
    sandbox: Sandbox,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planted = root / "python"
    planted.write_text("#!/bin/sh\n")
    planted.chmod(0o755)
    search = os.pathsep.join([str(root), str(Path(PYTHON).parent)])
    monkeypatch.setenv("PATH", search)
    assert sandbox.check(["python"], cwd=root).reason == "binary_not_allowed"


@posix_only
def test_planted_symlink_on_path_is_rejected(
    sandbox: Sandbox,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (root / "python").symlink_to(os.path.realpath(PYTHON))
    monkeypatch.setenv("PATH", str(root))
    assert sandbox.check(["python"], cwd=root).reason == "executable_in_roots"


def test_cwd_outside_roots(sandbox: Sandbox, tmp_path: Path) -> None:
    decision = sandbox.check([PYTHON, "-c", "pass"], cwd=tmp_path)
    assert decision.reason == "path_outside_roots"


@pytest.mark.parametrize(
    "arg",
    [
        "../x",
        "~/x",
        "--out=/etc/passwd",
        "--out=../x",
        "sub/../../x",
    ],
)
def test_paths_outside_roots(sandbox: Sandbox, root: Path, arg: str) -> None:
    assert sandbox.check([PYTHON, arg], cwd=root).reason == "path_outside_roots"


@pytest.mark.parametrize(
    "arg",
    [
        "--level=3",
        "a:b",
        "sub/file.txt",
        "./x",
        "-v",
        "--",
        "--out=out.txt",
    ],
)
def test_arguments_that_stay_inside_pass(sandbox: Sandbox, root: Path, arg: str) -> None:
    assert sandbox.check([PYTHON, arg], cwd=root).allowed is True


@posix_only
def test_symlink_pointing_outside_root(sandbox: Sandbox, root: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").symlink_to(outside)
    assert sandbox.check([PYTHON, "link/data.txt"], cwd=root).reason == "path_outside_roots"
    assert sandbox.check([PYTHON], cwd=root / "link").reason == "path_outside_roots"


@posix_only
def test_tilde_follows_home(
    sandbox: Sandbox,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(root))
    assert sandbox.check([PYTHON, "~/x"], cwd=root).allowed is True
    assert sandbox.check([PYTHON, "~no_such_user_zz/x"], cwd=root).reason == "path_outside_roots"


@pytest.mark.parametrize(
    "arg",
    [
        "a;b",
        "a|b",
        "a&b",
        "a$b",
        "a`b",
        "a>b",
        "a<b",
        "a\nb",
    ],
)
def test_shell_metacharacters_rejected(sandbox: Sandbox, root: Path, arg: str) -> None:
    assert sandbox.check([PYTHON, arg], cwd=root).reason == "shell_metacharacters"
    assert sandbox.check([arg], cwd=root).reason == "shell_metacharacters"


def test_metacharacters_pass_literally_when_allowed(loose: Policy, root: Path) -> None:
    sandbox = Sandbox(loose, runner=FakeProcessRunner())
    assert sandbox.check([PYTHON, "a;b"], cwd=root).allowed is True
    assert sandbox.check([PYTHON, "a\x00b"], cwd=root).reason == "shell_metacharacters"


def test_windows_string_command_requires_argv_list(
    sandbox: Sandbox,
    root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("agent_sandbox.sandbox._is_windows", lambda: True)
    decision = sandbox.check("C:\\tools\\x.exe y", cwd=root)
    assert decision.reason == "use_argv_list"
    assert decision.argv == ("C:\\tools\\x.exe", "y")


@posix_only
def test_string_command_is_parsed_with_shlex(sandbox: Sandbox, root: Path) -> None:
    decision = sandbox.check(f"{shlex.quote(PYTHON)} -c 'pass'", cwd=root)
    assert decision.allowed is True
    assert decision.argv == (PYTHON, "-c", "pass")
    assert sandbox.check("echo 'unterminated", cwd=root).reason == "use_argv_list"


@pytest.mark.parametrize(
    "command",
    [
        "",
        "   ",
        [],
        [""],
        ["  ", "x"],
        "''",
    ],
)
def test_empty_commands(sandbox: Sandbox, root: Path, command: Any) -> None:
    assert sandbox.check(command, cwd=root).reason == "empty_command"


def test_argv_limits(sandbox: Sandbox, root: Path) -> None:
    assert sandbox.check([PYTHON, *(["x"] * 255)], cwd=root).allowed is True
    too_many = sandbox.check([PYTHON, *(["x"] * 256)], cwd=root)
    assert too_many.reason == "argv_too_long"
    assert len(too_many.argv) <= 256
    assert sandbox.check([PYTHON, "x" * 4096], cwd=root).allowed is True
    assert sandbox.check([PYTHON, "x" * 4097], cwd=root).reason == "argv_too_long"
    assert sandbox.check("x " * 20000, cwd=root).reason == "argv_too_long"
    assert sandbox.check(" ".join(["a"] * 300), cwd=root).reason == "argv_too_long"
    huge = sandbox.check([PYTHON, *(["x"] * 1_000_000)], cwd=root)
    assert huge.reason == "argv_too_long"


@pytest.mark.parametrize("command", [b"ls", 123, [1, 2], None])
def test_invalid_command_type(sandbox: Sandbox, root: Path, command: Any) -> None:
    with pytest.raises(SandboxError) as info:
        sandbox.check(command, cwd=root)
    assert info.value.code == "invalid_command"


def test_allowed_run_uses_the_resolved_executable(
    sandbox: Sandbox,
    root: Path,
    fake: FakeProcessRunner,
    policy: Policy,
) -> None:
    result = sandbox.run([PYTHON, "-c", "pass"], cwd=root)
    assert result.exit_code == 0
    call = fake.calls[0]
    assert call.argv == (os.path.realpath(PYTHON), "-c", "pass")
    assert call.cwd == Path(os.path.realpath(root))
    assert call.timeout == policy.timeout_seconds
    assert call.max_bytes == policy.max_output_bytes


def test_child_environment_is_scrubbed(
    policy: Policy,
    root: Path,
    fake: FakeProcessRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("GITHUB_PAT", "aws_secret_key", "OAUTH_X", "PATTERN"):
        monkeypatch.setenv(name, "value")
    monkeypatch.setenv("PATH", os.defpath)
    allow = frozenset({"GITHUB_PAT", "aws_secret_key", "OAUTH_X", "PATTERN", "PATH"})
    guarded = Sandbox(replace(policy, env_allow=allow), runner=fake)
    guarded.run([PYTHON, "-c", "pass"], cwd=root)
    assert set(fake.calls[0].env) == {"PATH", "PATTERN"}


@pytest.mark.parametrize(
    "name",
    [
        "API_KEY",
        "github_token",
        "MY_SECRET",
        "DB_PASSWORD",
        "PASSWD",
        "AWS_CREDENTIALS",
        "OAUTH_X",
        "aws_secret_key",
        "GITHUB_PAT",
        "pat",
        "MY-PAT",
        "AUTHORIZATION",
    ],
)
def test_secret_like_names(name: str) -> None:
    assert is_secret_name(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "PATH",
        "PATTERN",
        "PATHEXT",
        "LANG",
        "TEMP",
        "SYSTEMROOT",
        "PATCH",
        "HOME",
    ],
)
def test_names_that_are_not_secret(name: str) -> None:
    assert is_secret_name(name) is False


def test_redaction_events_and_errors(policy: Policy, root: Path) -> None:
    events: list[Decision] = []
    sandbox = Sandbox(policy, runner=FakeProcessRunner(), on_event=events.append)
    argv = ["tool", "API_KEY=s3cr3t", "--token", "s3cr3t"]
    expected = ("tool", "API_KEY=[REDACTED]", "--token", "[REDACTED]")
    assert sandbox.check(argv, cwd=root).argv == expected
    with pytest.raises(PolicyViolation) as info:
        sandbox.run(argv, cwd=root)
    assert "s3cr3t" not in str(info.value)
    allowed = [PYTHON, "-c", "pass", "API_KEY=s3cr3t", "--token", "s3cr3t"]
    assert sandbox.check(allowed, cwd=root).allowed is True
    assert len(events) == 3
    assert events[0].argv == expected
    assert all("s3cr3t" not in repr(event) for event in events)
    assert all("s3cr3t" not in repr(entry) for entry in sandbox.audit())


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["tool", "--password=hunter2"], ("tool", "--password=[REDACTED]")),
        (["tool", "--api-key", "abc", "-v"], ("tool", "--api-key", "[REDACTED]", "-v")),
        (["tool", "--pat", "abc"], ("tool", "--pat", "[REDACTED]")),
        (["tool", "--pattern", "abc"], ("tool", "--pattern", "abc")),
        (["tool", "PATH=/bin"], ("tool", "PATH=/bin")),
        (["tool", "--token", "--auth", "x"], ("tool", "--token", "[REDACTED]", "[REDACTED]")),
    ],
)
def test_redaction_rules(
    sandbox: Sandbox,
    root: Path,
    argv: list[str],
    expected: tuple[str, ...],
) -> None:
    assert sandbox.check(argv, cwd=root).argv == expected


def test_audit_keeps_the_newest_entries(policy: Policy, root: Path) -> None:
    small = Sandbox(replace(policy, max_audit_entries=2), runner=FakeProcessRunner())
    for name in ("a1", "a2", "a3"):
        small.check([name], cwd=root)
    assert [entry.argv for entry in small.audit()] == [("a2",), ("a3",)]
    snapshot = small.audit()
    snapshot.clear()
    assert len(small.audit()) == 2


def test_failing_callback_does_not_break_checks(
    policy: Policy,
    root: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def boom(decision: Decision) -> None:
        raise RuntimeError("private detail")

    sandbox = Sandbox(policy, runner=FakeProcessRunner(), on_event=boom)
    with caplog.at_level(logging.INFO, logger="agent_sandbox"):
        decision = sandbox.check(["curl"], cwd=root)
    assert decision.reason == "binary_not_allowed"
    assert len(sandbox.audit()) == 1
    assert "private detail" not in caplog.text
    assert "on_event callback failed" in caplog.text

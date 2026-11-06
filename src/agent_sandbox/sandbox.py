"""The policy guard: ``Sandbox`` vets commands against a ``Policy`` and runs them.

See the package docstring for the threat model: this is a policy guard, not a security boundary.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

from .environment import scrub_env
from .errors import PolicyViolation, Reason, SandboxError
from .models import Decision, Policy, RunResult
from .paths import has_separator, is_inside, normalize
from .redaction import redact_argv
from .runner import ProcessRunner, SubprocessRunner

_log = logging.getLogger(__name__)

_MAX_ARGV = 256
_MAX_ELEMENT = 4096
_MAX_STRING = 32 * 1024
_META = re.compile(r"[;|&$`><\n]")
_BACKSLASH = "\\"


def _is_windows() -> bool:
    return sys.platform == "win32"


class _Deny(Exception):
    """Internal control flow: one of the ordered checks failed."""

    def __init__(self, reason: Reason, items: Sequence[str]) -> None:
        super().__init__(reason)
        self.reason: Reason = reason
        self.items = items


@dataclass(frozen=True)
class _Evaluation:
    decision: Decision
    reason: Reason | None
    argv: tuple[str, ...]
    env: dict[str, str]
    cwd: Path


def _audit_split(command: str) -> list[str]:
    return command[:_MAX_ELEMENT].split()[:_MAX_ARGV]


def _parse(command: str | Sequence[str]) -> list[str]:
    if isinstance(command, str):
        if not command or command.isspace():
            raise _Deny("empty_command", [])
        if len(command) > _MAX_STRING:
            raise _Deny("argv_too_long", _audit_split(command))
        if _is_windows() and _BACKSLASH in command:
            raise _Deny("use_argv_list", _audit_split(command))
        try:
            return shlex.split(command, posix=True)
        except ValueError:
            raise _Deny("use_argv_list", _audit_split(command)) from None
    if isinstance(command, bytes | bytearray) or not isinstance(command, Sequence):
        raise SandboxError("invalid_command", "command must be a string or list of strings")
    items = list(islice(command, _MAX_ARGV + 1))
    if not all(isinstance(item, str) for item in items):
        raise SandboxError("invalid_command", "every command element must be a string")
    return items


def _has_metacharacters(items: Sequence[str], reject: bool) -> bool:
    def flagged(item: str) -> bool:
        return "\x00" in item or (reject and _META.search(item) is not None)

    return any(flagged(item) for item in items)


def _is_relative_path(exe: str) -> bool:
    looks_like_path = has_separator(exe) or bool(os.path.splitdrive(exe)[0])
    return looks_like_path and not os.path.isabs(exe)


def _locate(exe: str, env: dict[str, str]) -> str | None:
    if os.path.isabs(exe):
        return exe
    found = shutil.which(exe, path=env.get("PATH", ""))
    return None if found is None else os.path.abspath(found)


def _path_value(arg: str) -> str | None:
    value = arg
    if arg.startswith("-") and "=" in arg:
        value = arg.partition("=")[2]
    if value.startswith((".", "~")) or has_separator(value):
        return value
    return None


def _argument_inside(arg: str, cwd_real: str, roots: list[str]) -> bool:
    value = _path_value(arg)
    if value is None:
        return True
    expanded = os.path.expanduser(value)
    if value.startswith("~") and expanded == value:
        return False
    target = expanded if os.path.isabs(expanded) else os.path.join(cwd_real, expanded)
    return is_inside(normalize(target), roots)


class Sandbox:
    """Checks commands against a ``Policy`` and runs the allowed ones.

    Every decision (from ``check`` and ``run``) is redacted, appended to a bounded audit log
    and passed to ``on_event``. This is a policy guard, not a security boundary.

    Args:
        policy: The immutable policy.
        runner: Executes vetted commands; defaults to ``SubprocessRunner``.
        clock: Monotonic clock handed to the default runner.
        on_event: Called with each redacted ``Decision``; its exceptions are swallowed.
    """

    def __init__(
        self,
        policy: Policy,
        runner: ProcessRunner | None = None,
        clock: Callable[[], float] = time.monotonic,
        on_event: Callable[[Decision], None] | None = None,
    ) -> None:
        if runner is None:
            runner = SubprocessRunner(clock=clock)
        self._policy = policy
        self._runner = runner
        self._on_event = on_event
        self._audit: deque[Decision] = deque(maxlen=policy.max_audit_entries)
        self._lock = threading.Lock()

    @property
    def policy(self) -> Policy:
        """The policy this sandbox enforces."""
        return self._policy

    def check(self, command: str | Sequence[str], cwd: Path) -> Decision:
        """Decide whether ``command`` may run in ``cwd``; nothing is executed.

        Checks run in a fixed order and the first failure wins: empty_command, argv_too_long,
        use_argv_list, shell_metacharacters, relative_executable, binary_not_allowed,
        executable_in_roots, path_outside_roots. A string that shlex cannot parse is denied as
        use_argv_list.

        Raises:
            SandboxError: with code ``invalid_command`` when ``command`` is not a string or a
                sequence of strings.
        """
        evaluation = self._evaluate(command, cwd)
        self._record(evaluation.decision)
        return evaluation.decision

    def run(self, command: str | Sequence[str], cwd: Path) -> RunResult:
        """Check ``command`` and run it when allowed.

        Raises:
            PolicyViolation: when the policy denies the command.
            SandboxError: ``invalid_command`` or ``spawn_failed``.
        """
        evaluation = self._evaluate(command, cwd)
        self._record(evaluation.decision)
        if evaluation.reason is not None:
            raise PolicyViolation(evaluation.reason, evaluation.decision)
        return self._runner.run(
            list(evaluation.argv),
            evaluation.cwd,
            evaluation.env,
            self._policy.timeout_seconds,
            self._policy.max_output_bytes,
        )

    def audit(self) -> list[Decision]:
        """Return a copy of the audit log, oldest first (at most ``max_audit_entries``)."""
        with self._lock:
            return list(self._audit)

    def _record(self, decision: Decision) -> None:
        with self._lock:
            self._audit.append(decision)
        if not decision.allowed:
            _log.info("command denied: %s", decision.reason)
        if self._on_event is None:
            return
        try:
            self._on_event(decision)
        except Exception as exc:
            _log.warning("on_event callback failed: %s", type(exc).__name__)

    def _evaluate(self, command: str | Sequence[str], cwd: Path) -> _Evaluation:
        env = scrub_env(self._policy.env_allow)
        try:
            items = _parse(command)
            argv, cwd_real = self._vet(items, cwd, env)
        except _Deny as denial:
            decision = Decision(False, denial.reason, redact_argv(denial.items))
            return _Evaluation(decision, denial.reason, (), env, Path(os.fspath(cwd)))
        decision = Decision(True, None, redact_argv(items))
        return _Evaluation(decision, None, argv, env, Path(cwd_real))

    def _vet(
        self,
        items: list[str],
        cwd: Path,
        env: dict[str, str],
    ) -> tuple[tuple[str, ...], str]:
        policy = self._policy
        if not items or not items[0].strip():
            raise _Deny("empty_command", items)
        if len(items) > _MAX_ARGV or any(len(item) > _MAX_ELEMENT for item in items):
            raise _Deny("argv_too_long", items)
        if _has_metacharacters(items, policy.reject_shell_metacharacters):
            raise _Deny("shell_metacharacters", items)
        exe = items[0]
        if _is_relative_path(exe):
            raise _Deny("relative_executable", items)
        candidate = _locate(exe, env)
        if candidate is None:
            raise _Deny("binary_not_allowed", items)
        real = os.path.realpath(candidate)
        allowed = {normalize(path) for path in policy.allowed_executables}
        if os.path.normcase(real) not in allowed:
            raise _Deny("binary_not_allowed", items)
        roots = [normalize(root) for root in policy.allowed_roots]
        parent = normalize(os.path.dirname(candidate))
        planted = os.path.join(parent, os.path.normcase(os.path.basename(candidate)))
        if is_inside(planted, roots):
            raise _Deny("executable_in_roots", items)
        cwd_real = os.path.realpath(os.fspath(cwd))
        if not is_inside(os.path.normcase(cwd_real), roots):
            raise _Deny("path_outside_roots", items)
        if not all(_argument_inside(arg, cwd_real, roots) for arg in items[1:]):
            raise _Deny("path_outside_roots", items)
        return (real, *items[1:]), cwd_real

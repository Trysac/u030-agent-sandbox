"""Immutable data types: policy, decisions and run results."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from .errors import SandboxError
from .paths import is_inside, normalize

_DEFAULT_ENV_NAMES = ("PATH", "PATHEXT", "LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP")

DEFAULT_ENV_ALLOW: frozenset[str] = frozenset(_DEFAULT_ENV_NAMES)


def _invalid(message: str) -> SandboxError:
    return SandboxError("invalid_policy", message)


@dataclass(frozen=True)
class Policy:
    """Immutable sandbox policy, validated on construction.

    Attributes:
        allowed_executables: Absolute paths of the only programs that may run. They are compared
            by ``os.path.normcase(os.path.realpath(p))``.
        allowed_roots: Absolute directories that the working directory and every path-like
            argument must stay inside. No allowed executable may live inside a root.
        timeout_seconds: Wall-clock limit for one run.
        max_output_bytes: Bytes kept per output stream; the rest is discarded.
        env_allow: Environment variable names the child may inherit. Secret-like names are
            dropped even when listed.
        reject_shell_metacharacters: Reject ``; | & $ ` > <`` and newline inside arguments.
        max_audit_entries: Size of the in-memory audit log (the newest entries are kept).

    Raises:
        SandboxError: with code ``invalid_policy`` when a value is not acceptable.
    """

    allowed_executables: frozenset[Path]
    allowed_roots: tuple[Path, ...]
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1_000_000
    env_allow: frozenset[str] = DEFAULT_ENV_ALLOW
    reject_shell_metacharacters: bool = True
    max_audit_entries: int = 1000

    def __post_init__(self) -> None:
        executables = frozenset(Path(item) for item in self.allowed_executables)
        roots = tuple(Path(item) for item in self.allowed_roots)
        object.__setattr__(self, "allowed_executables", executables)
        object.__setattr__(self, "allowed_roots", roots)
        object.__setattr__(self, "env_allow", frozenset(self.env_allow))
        if not all(path.is_absolute() for path in (*executables, *roots)):
            raise _invalid("executables and roots must be absolute paths")
        if not (math.isfinite(self.timeout_seconds) and self.timeout_seconds > 0):
            raise _invalid("timeout_seconds must be a positive finite number")
        if self.max_output_bytes < 1:
            raise _invalid("max_output_bytes must be at least 1")
        if self.max_audit_entries < 1:
            raise _invalid("max_audit_entries must be at least 1")
        real_roots = [normalize(root) for root in roots]
        if any(is_inside(normalize(exe), real_roots) for exe in executables):
            raise _invalid("an allowed executable must not be inside an allowed root")


@dataclass(frozen=True)
class Decision:
    """Outcome of a policy check.

    Attributes:
        allowed: Whether the command may run.
        reason: ``None`` when allowed, otherwise the denial reason.
        argv: The command as audited: secrets redacted, elements cut to 200 characters.
    """

    allowed: bool
    reason: str | None
    argv: tuple[str, ...]


@dataclass(frozen=True)
class RunResult:
    """Result of running a command.

    Attributes:
        exit_code: Exit status, or ``None`` when the run timed out.
        stdout: Captured standard output (at most ``max_output_bytes``), decoded with replacement.
        stderr: Captured standard error, same rules.
        timed_out: Whether the process tree was killed because of the timeout.
        truncated: Whether either stream produced more than ``max_output_bytes``.
        duration_seconds: Elapsed time according to the injected clock.
    """

    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool
    duration_seconds: float

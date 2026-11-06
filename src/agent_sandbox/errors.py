"""Typed errors raised by ``agent_sandbox``."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .models import Decision

# Machine-readable reasons for which a command is denied.
Reason = Literal[
    "empty_command",
    "argv_too_long",
    "use_argv_list",
    "shell_metacharacters",
    "relative_executable",
    "binary_not_allowed",
    "executable_in_roots",
    "path_outside_roots",
]

_MAX_MESSAGE_INPUT = 200


class SandboxError(Exception):
    """Base class of every error raised by this library.

    Attributes:
        code: Stable machine-readable error code, for example ``invalid_policy``.
    """

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message if message is not None else code)
        self.code = code


class PolicyViolation(SandboxError):
    """Raised by ``Sandbox.run`` when the policy denies a command.

    The message holds the reason and at most 200 characters of the redacted command.

    Attributes:
        reason: Why the command was denied.
        decision: The redacted decision that was audited.
    """

    def __init__(self, reason: Reason, decision: Decision) -> None:
        detail = " ".join(decision.argv)[:_MAX_MESSAGE_INPUT]
        super().__init__("policy_violation", f"{reason}: {detail}")
        self.reason: Reason = reason
        self.decision = decision

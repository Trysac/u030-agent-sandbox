"""Policy guard for agent shell commands.

THREAT MODEL: ``agent_sandbox`` is a policy guard, NOT a security boundary. It sits in front of
``subprocess``: a deterministic check allows or denies a command before anything runs, then the
command runs with a scrubbed environment, a wall-clock timeout (the whole process tree is killed)
and capped output.

Defended: binaries that are not allow-listed, binaries planted in the workspace, PATH hijacking,
paths outside the allowed roots, secrets leaking through the environment, runaway run time and
runaway output.

Not defended: interpreters or shells in the allow list grant arbitrary code execution; path
checks are TOCTOU-racy; memory, CPU and network are not limited (use containers for that); the
semantics of allowed tools (``git -c``, ``find -exec``) are not inspected.
"""

from __future__ import annotations

import logging

from .errors import PolicyViolation, Reason, SandboxError
from .models import DEFAULT_ENV_ALLOW, Decision, Policy, RunResult
from .redaction import is_secret_name
from .runner import ProcessRunner, SubprocessRunner
from .sandbox import Sandbox

logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "DEFAULT_ENV_ALLOW",
    "Decision",
    "Policy",
    "PolicyViolation",
    "ProcessRunner",
    "Reason",
    "RunResult",
    "Sandbox",
    "SandboxError",
    "SubprocessRunner",
    "__version__",
    "is_secret_name",
]

__version__ = "0.1.0"
